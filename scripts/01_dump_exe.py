#!/usr/bin/env python3
"""
01_dump_exe.py — Dump do GrandChase.exe desprotegido (Themida) da memória
=========================================================================

O Themida descomprime o código em runtime. Este script espera o jogo
desempacotar e então faz dump do módulo inteiro para análise no Ghidra.

Uso:
  1. Abra o GrandChase pela Epic Games, espere a tela de login aparecer
  2. python scripts/01_dump_exe.py
  3. Abra o dump no Ghidra: File → Import → grandchase_unpacked.bin
     - Format: Raw Binary (ou PE)
     - Architecture: x86-64

Saída:
  output/grandchase_unpacked.bin
"""
import os
import sys
import time
import subprocess
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
OUTPUT_DIR = os.path.join(TOOLKIT_ROOT, "output")

PROCESS_NAME = "GrandChase.exe"
DELAY_MS = 12000  # ms para Themida desempacotar

# Bytes conhecidos para verificar se o unpack completou
UNPACK_CHECK_RVA = 0x13e8310
UNPACK_EXPECTED = [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83,
                   0xec, 0x20, 0x48, 0x8b, 0x81, 0x88, 0x00, 0x00, 0x00]


def find_pid():
    try:
        import frida
        device = frida.get_local_device()
        for proc in device.enumerate_processes():
            if proc.name.lower() in ["grandchase.exe", "fantasybin.exe"]:
                return proc.pid
    except Exception:
        pass
    # Fallback: tasklist
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


JS_DUMP = r"""
'use strict';
var DELAY_MS = __DELAY_MS__;
var EXPECTED = __EXPECTED__;
var CHECK_RVA = __CHECK_RVA__;

function emit(o, data) { if (data) send(o, data); else send(o); }
emit({type:'info', msg:'Conectado! Aguardando ' + DELAY_MS + 'ms para Themida...'});

setTimeout(function() {
    var mod = Process.findModuleByName('GrandChase.exe');
    if (!mod) { emit({type:'error', msg:'Módulo não encontrado'}); return; }
    emit({type:'info', msg:'Módulo: ' + mod.base + ' size=' + mod.size});

    // Verificar unpack
    try {
        var raw = mod.base.add(CHECK_RVA).readByteArray(EXPECTED.length);
        var a = new Uint8Array(raw);
        var ok = true;
        for (var i = 0; i < EXPECTED.length; i++) { if (a[i] !== EXPECTED[i]) { ok = false; break; } }
        emit({type:'info', msg: ok ? 'Unpack verificado!' : 'Bytes diferem, fazendo dump mesmo assim...'});
    } catch(e) {
        emit({type:'info', msg:'Não foi possível verificar unpack, continuando...'});
    }

    // Dump por chunks de 1MB
    var CHUNK = 1024 * 1024;
    var offset = 0;
    while (offset < mod.size) {
        var sz = Math.min(CHUNK, mod.size - offset);
        var chunk = mod.base.add(offset).readByteArray(sz);
        send({type:'chunk', offset: offset, size: sz}, chunk);
        offset += sz;
    }
    send({type:'done', base: mod.base.toString(), size: mod.size});
}, DELAY_MS);
"""


def main():
    parser = argparse.ArgumentParser(description="Dump GrandChase.exe desprotegido da memória")
    parser.add_argument("-o", "--output", default=os.path.join(OUTPUT_DIR, "grandchase_unpacked.bin"))
    parser.add_argument("--delay", type=int, default=DELAY_MS, help="Delay em ms para Themida (default: 12000)")
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

    print(f"[+] PID: {pid}")
    print(f"[*] Conectando...")

    session = frida.attach(pid)

    js = JS_DUMP.replace("__DELAY_MS__", str(args.delay))
    js = js.replace("__EXPECTED__", json.dumps(UNPACK_EXPECTED))
    js = js.replace("__CHECK_RVA__", str(UNPACK_CHECK_RVA))

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    chunks = {}
    info = {}

    def on_message(message, data):
        if message["type"] != "send":
            if message["type"] == "error":
                print(f"[!] {message.get('description', '')}")
            return
        p = message["payload"]
        t = p.get("type", "")
        if t == "info":
            print(f"[*] {p['msg']}")
        elif t == "error":
            print(f"[!] {p['msg']}")
        elif t == "chunk" and data:
            chunks[p["offset"]] = data
            mb = (p["offset"] + p["size"]) / (1024 * 1024)
            print(f"\r[*] Dump: {mb:.1f} MB...", end="", flush=True)
        elif t == "done":
            info["base"] = p.get("base", "?")
            info["size"] = p.get("size", 0)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    # Aguardar dump
    timeout = (args.delay / 1000) + 60
    start = time.time()
    while "size" not in info and (time.time() - start) < timeout:
        time.sleep(0.5)

    time.sleep(2)  # chunks finais

    try:
        script.unload()
    except Exception:
        pass

    if not chunks:
        print("\n[!] Nenhum dado recebido!")
        sys.exit(1)

    # Escrever dump
    with open(args.output, "wb") as f:
        for off in sorted(chunks.keys()):
            f.write(chunks[off])

    size = os.path.getsize(args.output)
    print(f"\n[+] Dump salvo: {args.output}")
    print(f"    Tamanho: {size:,} bytes ({size/1024/1024:.1f} MB)")
    print(f"    Base: {info.get('base', '?')}")
    print(f"\n[*] Abra no Ghidra para análise estática.")


if __name__ == "__main__":
    main()
