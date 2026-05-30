#!/usr/bin/env python3
"""
02_find_offsets.py — Encontra novos offsets das funções crypto após atualização
===============================================================================

Após uma atualização do jogo, os endereços das funções crypto mudam.
Este script usa assinaturas de bytes para localizar automaticamente
os novos RVAs e atualiza o offsets.json.

Assinaturas usadas:
  - CIPHER_INIT (19 bytes) — Init AES, captura chave 32B
  - MODE_INIT   (24 bytes) — Init CBC, captura IV 16B (mais única)
  - BULK_DEC    (22 bytes) — Decrypt em bloco

Regra de validação cruzada:
  MODE_INIT está sempre exatamente 0xC0 bytes depois de CIPHER_INIT.

Uso:
  1. Abra o GrandChase pela Epic, espere a tela de login
  2. python scripts/02_find_offsets.py
  3. Verifique os novos offsets e confirme a atualização

Saída:
  keys/offsets.json (atualizado com novos RVAs)
"""
import os
import sys
import json
import time
import subprocess
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
OFFSETS_PATH = os.path.join(TOOLKIT_ROOT, "keys", "offsets.json")
PROCESS_NAME = "GrandChase.exe"

# Assinaturas de bytes (imunem a realocação, mudam raramente)
SIGNATURES = {
    "CIPHER_INIT": {
        "scan_hex": "4c89442418488954241048894c24084883ec28",
        "description": "Init AES — captura chave 32B",
    },
    "MODE_INIT": {
        "scan_hex": "44894c24204c89442418488954241048894c24084883ec28",
        "description": "Init CBC mode — captura IV 16B",
    },
    "BULK_DEC": {
        "scan_hex": "4883ec38488b0144884c24204533c9ff50304883c438c3",
        "description": "Decrypt em bloco",
    },
}

# Gap fixo entre CIPHER_INIT e MODE_INIT
CI_TO_MI_GAP = 0xC0


def find_pid():
    try:
        import frida
        device = frida.get_local_device()
        for proc in device.enumerate_processes():
            if proc.name.lower() in ["grandchase.exe", "fantasybin.exe"]:
                return proc.pid
    except Exception:
        pass
    try:
        cp = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {PROCESS_NAME}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=False)
        for line in (cp.stdout or "").strip().splitlines():
            parts = [x.strip().strip('"') for x in line.split(",")]
            if len(parts) >= 2 and parts[0].lower() == PROCESS_NAME.lower():
                return int(parts[1])
    except Exception:
        pass
    return None


JS_SCAN = r"""
'use strict';
var SIGS = __SIGNATURES__;
var mod = Process.getModuleByName('GrandChase.exe');
if (!mod) {
    send({type:'error', msg:'GrandChase.exe não encontrado'});
} else {
    send({type:'info', base: mod.base.toString(), size: mod.size});
    var results = {};
    for (var name in SIGS) {
        var hex = SIGS[name].scan_hex;
        var pattern = '';
        for (var i = 0; i < hex.length; i += 2) {
            if (i > 0) pattern += ' ';
            pattern += hex.substring(i, i + 2);
        }
        var matches = Memory.scanSync(mod.base, mod.size, pattern);
        var rvas = [];
        for (var j = 0; j < matches.length; j++) {
            rvas.push(matches[j].address.sub(mod.base).toInt32());
        }
        results[name] = rvas;
    }
    send({type:'done', results: results, moduleSize: mod.size});
}
"""


def resolve_offsets(results):
    """Resolve ambiguidades usando regras de validação cruzada."""
    resolved = {}

    # MODE_INIT é a mais única (geralmente 1-2 matches)
    mi_candidates = results.get("MODE_INIT", [])
    ci_candidates = results.get("CIPHER_INIT", [])
    bd_candidates = results.get("BULK_DEC", [])

    # Resolver MODE_INIT + CIPHER_INIT pelo gap de 0xC0
    if len(mi_candidates) == 1:
        resolved["MODE_INIT"] = mi_candidates[0]
        expected_ci = mi_candidates[0] - CI_TO_MI_GAP
        if expected_ci in ci_candidates:
            resolved["CIPHER_INIT"] = expected_ci
        elif ci_candidates:
            print(f"  [!] CIPHER_INIT esperado em 0x{expected_ci:x} não encontrado nos matches")
            print(f"      Matches: {[hex(x) for x in ci_candidates]}")
            # Usar o match mais próximo
            closest = min(ci_candidates, key=lambda x: abs(x - expected_ci))
            print(f"      Usando mais próximo: 0x{closest:x}")
            resolved["CIPHER_INIT"] = closest
    elif len(mi_candidates) > 1:
        print(f"  [!] MODE_INIT tem {len(mi_candidates)} matches, usando validação cruzada...")
        for mi in mi_candidates:
            expected_ci = mi - CI_TO_MI_GAP
            if expected_ci in ci_candidates:
                resolved["MODE_INIT"] = mi
                resolved["CIPHER_INIT"] = expected_ci
                print(f"      Par válido: CI=0x{expected_ci:x} MI=0x{mi:x}")
                break
        if "MODE_INIT" not in resolved and mi_candidates:
            resolved["MODE_INIT"] = mi_candidates[0]
            resolved["CIPHER_INIT"] = mi_candidates[0] - CI_TO_MI_GAP
            print(f"      Usando primeiro match (sem validação cruzada)")

    # CIPHER_INIT standalone (se ainda não resolvido)
    if "CIPHER_INIT" not in resolved and ci_candidates:
        if len(ci_candidates) == 1:
            resolved["CIPHER_INIT"] = ci_candidates[0]
        else:
            # Se MODE_INIT foi resolvido, usar o gap
            if "MODE_INIT" in resolved:
                resolved["CIPHER_INIT"] = resolved["MODE_INIT"] - CI_TO_MI_GAP

    # BULK_DEC
    if len(bd_candidates) == 1:
        resolved["BULK_DEC"] = bd_candidates[0]
    elif bd_candidates:
        resolved["BULK_DEC"] = bd_candidates[0]
        if len(bd_candidates) > 1:
            print(f"  [!] BULK_DEC tem {len(bd_candidates)} matches, usando primeiro")

    return resolved


def update_offsets_file(resolved, module_size):
    """Atualiza o offsets.json com os novos valores."""
    try:
        with open(OFFSETS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {"aes": {}, "history": []}

    from datetime import datetime
    date_str = datetime.now().strftime("%Y-%m")

    # Atualizar seção AES
    for name, rva in resolved.items():
        if name in data.get("aes", {}):
            data["aes"][name]["rva"] = f"0x{rva:x}"
        else:
            data.setdefault("aes", {})[name] = {"rva": f"0x{rva:x}"}

    data["_updated"] = date_str
    data["_module_size"] = module_size

    # Adicionar ao histórico
    entry = {"date": date_str, "module_size": module_size}
    for name, rva in resolved.items():
        entry[name] = f"0x{rva:x}"
    data.setdefault("history", []).append(entry)

    with open(OFFSETS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"\n  [+] offsets.json atualizado: {OFFSETS_PATH}")


def main():
    parser = argparse.ArgumentParser(description="Encontra novos offsets crypto no GrandChase.exe")
    parser.add_argument("--no-update", action="store_true", help="Não atualizar offsets.json")
    parser.add_argument("--dump", action="store_true", help="Também fazer dump do módulo")
    args = parser.parse_args()

    try:
        import frida
    except ImportError:
        print("[!] Frida não instalado. Rode: pip install frida frida-tools")
        sys.exit(1)

    pid = find_pid()
    if not pid:
        print(f"[!] {PROCESS_NAME} não encontrado. Abra o jogo primeiro.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  GrandChase Offset Finder")
    print(f"{'='*60}")
    print(f"  PID: {pid}")

    session = frida.attach(pid)
    print(f"  Conectado!")

    sigs_json = json.dumps({
        name: {"scan_hex": s["scan_hex"]}
        for name, s in SIGNATURES.items()
    })
    js = JS_SCAN.replace("__SIGNATURES__", sigs_json)

    scan_results = {}
    module_size = 0

    def on_message(message, data):
        nonlocal scan_results, module_size
        if message["type"] != "send":
            if message["type"] == "error":
                print(f"  [!] {message.get('description', '')}")
            return
        p = message["payload"]
        t = p.get("type", "")
        if t == "info":
            print(f"  [*] Módulo: {p.get('base', '')} size={p.get('size', '')}")
            module_size = p.get("size", 0)
        elif t == "done":
            scan_results = p.get("results", {})
            module_size = p.get("moduleSize", module_size)
        elif t == "error":
            print(f"  [!] {p['msg']}")

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    time.sleep(5)

    try:
        script.unload()
    except Exception:
        pass

    if not scan_results:
        print("  [!] Nenhum resultado!")
        sys.exit(1)

    # Mostrar resultados brutos
    print(f"\n  Resultados da busca:")
    print(f"  {'─'*50}")
    for name, rvas in scan_results.items():
        count = len(rvas)
        status = "OK" if count == 1 else ("MÚLTIPLOS" if count > 1 else "NÃO ENCONTRADO")
        rva_str = ", ".join(f"0x{r:x}" for r in rvas) if rvas else "—"
        desc = SIGNATURES.get(name, {}).get("description", "")
        print(f"  [{status:>15}] {name:<15} = {rva_str}")
        if desc:
            print(f"  {'':>17} {desc}")

    # Resolver ambiguidades
    resolved = resolve_offsets(scan_results)
    if not resolved:
        print("\n  [!] Nenhum offset resolvido!")
        sys.exit(1)

    print(f"\n  Offsets resolvidos:")
    print(f"  {'─'*50}")
    for name, rva in resolved.items():
        print(f"  {name:<15} = 0x{rva:x}")

    # Validar gap
    if "CIPHER_INIT" in resolved and "MODE_INIT" in resolved:
        gap = resolved["MODE_INIT"] - resolved["CIPHER_INIT"]
        ok = "✓" if gap == CI_TO_MI_GAP else "✗"
        print(f"\n  Gap CI→MI: 0x{gap:x} (esperado: 0x{CI_TO_MI_GAP:x}) {ok}")

    # Carregar offsets anteriores para comparação
    try:
        with open(OFFSETS_PATH, "r", encoding="utf-8") as f:
            old = json.load(f)
        old_aes = old.get("aes", {})
        changed = False
        for name, rva in resolved.items():
            old_rva = old_aes.get(name, {}).get("rva", "")
            if old_rva and int(old_rva, 16) != rva:
                changed = True
                print(f"  [MUDOU] {name}: {old_rva} → 0x{rva:x}")
        if not changed:
            print(f"\n  Nenhuma mudança detectada — offsets iguais aos atuais.")
    except FileNotFoundError:
        pass

    # Atualizar
    if not args.no_update:
        update_offsets_file(resolved, module_size)

    print()


if __name__ == "__main__":
    main()
