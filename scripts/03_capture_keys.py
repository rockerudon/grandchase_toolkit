#!/usr/bin/env python3
"""
03_capture_keys.py — Captura chaves AES-256-CBC em runtime via Frida
====================================================================

Instala hooks nas funcoes CIPHER_INIT e MODE_INIT do GrandChase.exe
para capturar chaves AES (32 bytes) e IVs (16 bytes).

Pareamento por CONTEXTO:
  CIPHER_INIT(rcx=ctx_out, rdx=key_ptr, r8d=key_len)
  MODE_INIT(rcx=out, rdx=cipher_ctx, r8=iv_ptr, r9d=dir)
  → ctx_out de CIPHER_INIT == cipher_ctx de MODE_INIT
  → Pareia key<->IV pela identidade do ponteiro do contexto.

Uso:
  .venv\\Scripts\\python.exe scripts\\03_capture_keys.py                    # Captura continua
  .venv\\Scripts\\python.exe scripts\\03_capture_keys.py --duration 120     # Para apos 120s
  .venv\\Scripts\\python.exe scripts\\03_capture_keys.py --auto-merge       # Salva em algo3_keys.json

Saida:
  keys/captured_keys.jsonl  — log de todas as chaves capturadas
  keys/algo3_keys.json      — (com --auto-merge) base atualizada
"""
import ctypes
import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
KEYS_DIR = os.path.join(TOOLKIT_ROOT, "keys")
OFFSETS_PATH = os.path.join(KEYS_DIR, "offsets.json")
ALGO3_PATH = os.path.join(KEYS_DIR, "algo3_keys.json")
CAPTURE_LOG = os.path.join(KEYS_DIR, "captured_keys.jsonl")
PROCESS_NAME = "GrandChase.exe"


# ── Helpers ──────────────────────────────────────────────────────────────

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def load_offsets():
    with open(OFFSETS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    aes = data.get("aes", {})
    return {
        "CIPHER_INIT": int(aes["CIPHER_INIT"]["rva"], 16),
        "MODE_INIT": int(aes["MODE_INIT"]["rva"], 16),
    }


def load_existing_keys():
    try:
        with open(ALGO3_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return {(p["key"].lower(), p["iv"].lower()) for p in data.get("pairs", [])}
    except FileNotFoundError:
        return set()


def _find_pid(device, pname):
    try:
        for p in device.enumerate_processes():
            if p.name.lower() == pname.lower():
                return int(p.pid)
    except Exception:
        pass
    return None


def _find_pid_tasklist(pname):
    try:
        cp = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {pname}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=False)
        out = (cp.stdout or "").strip()
        if not out or "No tasks" in out:
            return None
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("INFO:"):
                continue
            parts = [x.strip().strip('"') for x in line.split(",")]
            if len(parts) >= 2:
                return int(parts[1])
    except Exception:
        pass
    return None


def try_attach(device, pid, timeout=30):
    """Tenta attach com retry (Themida bloqueia temporariamente)."""
    end = time.time() + timeout
    last = None
    attempt = 0
    while time.time() < end:
        try:
            attempt += 1
            return device.attach(pid)
        except Exception as e:
            last = e
            if attempt <= 3 or attempt % 10 == 0:
                remaining = int(end - time.time())
                print(f"  [.] Attach tentativa #{attempt} ({remaining}s): {type(e).__name__}")
            time.sleep(0.5)
    if last:
        raise last
    raise RuntimeError("attach failed")


# ── JavaScript — pareamento por CONTEXTO (ponteiro do cipher ctx) ────────
# CIPHER_INIT.args[0] (rcx=ctx_out) == MODE_INIT.args[1] (rdx=cipher_ctx)
# Hooks sao instalados DENTRO de setTimeout para esperar Themida desempacotar.
JS_SRC = r"""
'use strict';

var DELAY_MS        = __DELAY_MS__;
var CIPHER_INIT_OFF = __CIPHER_INIT_OFF__;
var MODE_INIT_OFF   = __MODE_INIT_OFF__;

function hex(ptr, len) {
  try {
    var buf = ptr.readByteArray(len);
    if (!buf) return '';
    var a = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < a.length; i++) {
      var h = a[i].toString(16);
      s += (h.length < 2 ? '0' : '') + h;
    }
    return s;
  } catch(e) { return ''; }
}

setTimeout(function() {
  var mod = Process.getModuleByName('GrandChase.exe');
  if (!mod) {
    send({type:'error', msg:'GrandChase.exe nao encontrado no processo!'});
    return;
  }
  var base = mod.base;
  send({type:'status', msg:'Modulo encontrado', base: base.toString(), size: mod.size});

  // Mapa: ponteiro do contexto -> chave hex
  var ctxToKey = {};
  var pairN = 0;

  // === CIPHER_INIT: captura chave AES e registra no mapa por contexto ===
  Interceptor.attach(base.add(CIPHER_INIT_OFF), {
    onEnter: function(args) {
      this._ctxPtr = args[0].toString();   // rcx = ponteiro de saida do contexto
      this._keyLen = args[2].toInt32();
      this._keyHex = hex(args[1], Math.min(this._keyLen, 64));
    },
    onLeave: function(retval) {
      if (this._keyLen === 32 && this._keyHex.length === 64) {
        ctxToKey[this._ctxPtr] = this._keyHex;
      }
      send({
        type: 'cipher_init',
        ctx: this._ctxPtr,
        keyLen: this._keyLen,
        key: this._keyHex,
      });
    }
  });

  // === MODE_INIT: captura IV e pareia via ponteiro do contexto ===
  Interceptor.attach(base.add(MODE_INIT_OFF), {
    onEnter: function(args) {
      this._cipherCtx = args[1].toString();  // rdx = mesmo ponteiro que CIPHER_INIT.args[0]
      this._dir = args[3].toInt32();
      this._ivHex = hex(args[2], 16);
    },
    onLeave: function(retval) {
      var key = ctxToKey[this._cipherCtx];
      if (key && this._dir === 0 && this._ivHex.length === 32) {
        pairN++;
        send({
          type: 'pair',
          n: pairN,
          key: key,
          iv: this._ivHex,
          ctx: this._cipherCtx,
        });
      }
      send({
        type: 'mode_init',
        ctx: this._cipherCtx,
        dir: this._dir,
        iv: this._ivHex,
        paired: key ? true : false,
      });
    }
  });

  send({type:'status', msg:'Hooks instalados (pareamento por contexto). Aguardando atividade crypto...'});
}, DELAY_MS);
"""


# ── Classe de captura — pareamento por CONTEXTO (direto do JS) ───────────
class KeyCapture:
    def __init__(self, existing_keys, target_tester=None):
        self.existing = existing_keys
        self.target_tester = target_tester
        self.events = []

        self.confirmed_pairs = set()
        self.new_pairs = set()

        self.stats = {"cipher_init": 0, "mode_init": 0, "pairs": 0}
        self.unique_keys = 0
        self.unique_ivs = 0
        self._seen_keys = set()
        self._seen_ivs = set()
        self._unpaired_mi = 0  # MODE_INIT sem contexto correspondente

    def handle(self, payload, log_file=None):
        t = payload.get("type", "")
        self.events.append(payload)

        if t == "cipher_init":
            self.stats["cipher_init"] += 1
            key = payload.get("key", "").lower()
            kl = payload.get("keyLen", 0)
            if kl == 32 and len(key) == 64:
                if key not in self._seen_keys:
                    self._seen_keys.add(key)
                    self.unique_keys += 1
                    print(f"  [KEY #{self.unique_keys:3d}] {key[:32]}...  (256-bit)")

        elif t == "mode_init":
            self.stats["mode_init"] += 1
            iv = payload.get("iv", "").lower()
            d = payload.get("dir", -1)
            paired = payload.get("paired", False)
            if d == 0 and len(iv) == 32:
                if iv not in self._seen_ivs:
                    self._seen_ivs.add(iv)
                    self.unique_ivs += 1
                    print(f"  [IV  #{self.unique_ivs:3d}] {iv}    (decrypt)")
                if not paired:
                    self._unpaired_mi += 1

        elif t == "pair":
            self.stats["pairs"] += 1
            key = payload.get("key", "").lower()
            iv = payload.get("iv", "").lower()
            self._register_pair(key, iv, payload.get("n", 0), log_file)

        elif t == "status":
            print(f"  [*] {payload.get('msg', '')}")

        elif t == "error":
            print(f"  [!] {payload.get('msg', '')}")

        if log_file and t in ("cipher_init", "mode_init", "pair"):
            payload["ts"] = datetime.now().isoformat()
            log_file.write(json.dumps(payload) + "\n")
            log_file.flush()

    def _register_pair(self, key, iv, n, log_file=None):
        pair = (key, iv)
        if pair in self.confirmed_pairs:
            return
        self.confirmed_pairs.add(pair)
        is_new = pair not in self.existing
        if is_new:
            self.new_pairs.add(pair)
        tag = "NOVO" if is_new else "EXISTENTE"
        print(f"  [{tag}] Par #{len(self.confirmed_pairs)}: key={key[:16]}... iv={iv[:8]}...")

        # Testar contra KOMs pendentes
        if is_new and self.target_tester:
            solved = self.target_tester.test_pair(key, iv)
            for name in solved:
                print(f"  [!!] CHAVE ENCONTRADA para {name}.kom!")
            if self.target_tester.pending:
                print(self.target_tester.status_line())
            elif self.target_tester.solved:
                print(f"  [**] TODOS os KOMs alvo resolvidos! Pode parar a captura.")

        if log_file:
            entry = {"ts": datetime.now().isoformat(), "type": "confirmed",
                     "key": key, "iv": iv, "new": is_new, "n": n}
            log_file.write(json.dumps(entry) + "\n")
            log_file.flush()

    def summary(self):
        lines = [
            "",
            "=" * 64,
            "  RESUMO DA CAPTURA",
            "=" * 64,
            f"  Eventos: ci={self.stats['cipher_init']}  mi={self.stats['mode_init']}  pairs={self.stats['pairs']}",
            f"  Chaves unicas: {self.unique_keys}   IVs unicos: {self.unique_ivs}",
            f"  Pares confirmados (ctx-match): {len(self.confirmed_pairs)}",
            f"    Ja existentes no banco: {len(self.confirmed_pairs) - len(self.new_pairs)}",
            f"    *** NOVOS: {len(self.new_pairs)} ***",
            f"  MODE_INIT sem contexto: {self._unpaired_mi}",
        ]
        if self.new_pairs:
            lines.append("")
            lines.append("  NOVAS CHAVES CAPTURADAS:")
            for i, (k, iv) in enumerate(sorted(self.new_pairs), 1):
                lines.append(f"    {i}. Key: {k}")
                lines.append(f"       IV:  {iv}")
        elif self.confirmed_pairs:
            lines.append("  (todas as chaves capturadas ja estavam no banco)")
        else:
            lines.append("  (nenhum par foi confirmado nesta sessao)")
        lines.append("=" * 64)
        return "\n".join(lines)


# ── Teste em tempo real contra KOMs faltantes ───────────────────────────

class TargetTester:
    """Testa cada novo par contra arquivos encrypted de KOMs pendentes."""

    def __init__(self, target_koms):
        self.pending = {}    # nome_kom -> [filepath, ...]
        self.solved = {}     # nome_kom -> (key, iv)
        extracted_root = os.path.join(TOOLKIT_ROOT, "output", "extracted")
        for name in target_koms:
            dpath = os.path.join(extracted_root, name)
            if not os.path.isdir(dpath):
                continue
            sample_files = []
            for fn in os.listdir(dpath):
                if fn.endswith((".lua", ".stg", ".kstg")):
                    fp = os.path.join(dpath, fn)
                    sz = os.path.getsize(fp)
                    if sz >= 16 and sz % 16 == 0:
                        sample_files.append(fp)
                        if len(sample_files) >= 3:
                            break
            if sample_files:
                self.pending[name] = sample_files

    def test_pair(self, key_hex, iv_hex):
        """Testa um par contra todos os KOMs pendentes. Retorna lista de KOMs resolvidos."""
        if not self.pending:
            return []
        from Crypto.Cipher import AES
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        newly_solved = []
        for name in list(self.pending.keys()):
            for fp in self.pending[name]:
                try:
                    with open(fp, "rb") as f:
                        data = f.read(48)
                    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(data[:48])
                    if dec[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
                        self.solved[name] = (key_hex, iv_hex)
                        del self.pending[name]
                        newly_solved.append(name)
                        break
                except Exception:
                    pass
        return newly_solved

    def status_line(self):
        if not self.pending and not self.solved:
            return "  (sem KOMs alvo)"
        parts = []
        for name in sorted(self.solved):
            parts.append(f"{name}=OK")
        for name in sorted(self.pending):
            parts.append(f"{name}=???")
        return "  KOMs: " + "  ".join(parts)


# ── Merge ────────────────────────────────────────────────────────────────

def merge_into_algo3(new_pairs):
    try:
        with open(ALGO3_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {
            "_comment": "Chaves AES-256-CBC capturadas via Frida para Algorithm 3",
            "_cipher": "AES-256-CBC",
            "_pipeline": "AES-CBC(key,iv) -> zlib -> Blowfish-ECB -> KL bytecode",
            "pairs": []
        }

    existing = {(p["key"].lower(), p["iv"].lower()) for p in data["pairs"]}
    added = 0
    for key, iv in new_pairs:
        if (key, iv) not in existing:
            data["pairs"].append({"key": key, "iv": iv})
            existing.add((key, iv))
            added += 1

    if added > 0:
        data["pairs"].sort(key=lambda x: x["key"])
        with open(ALGO3_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n  [+] {added} novos pares adicionados a algo3_keys.json (total: {len(data['pairs'])})")
    else:
        print(f"\n  [*] Nenhum par novo — todos ja existiam ({len(data['pairs'])} pares)")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Captura chaves AES-256-CBC do GrandChase via Frida")
    parser.add_argument("--duration", type=int, default=600, help="Duracao em segundos (default: 600)")
    parser.add_argument("--delay", type=int, default=1, help="Delay JS em segundos antes de instalar hooks (default: 1)")
    parser.add_argument("--auto-merge", action="store_true", help="Merge automatico em algo3_keys.json")
    parser.add_argument("--target-koms", nargs="+", default=None,
                        help="KOMs faltantes para testar em tempo real (ex: ui SubjectAction string)")
    args = parser.parse_args()

    try:
        import frida
    except ImportError:
        print("[!] Frida nao instalado. Rode: pip install frida frida-tools")
        sys.exit(1)

    try:
        offsets = load_offsets()
    except Exception as e:
        print(f"[!] Erro ao carregar offsets.json: {e}")
        print("    Rode 02_find_offsets.py primeiro.")
        sys.exit(1)

    if not is_admin():
        print("[!] AVISO: Nao esta rodando como Administrador!")
        print("[!] O Frida pode precisar de admin para injetar no GrandChase.")

    existing_keys = load_existing_keys()
    print(f"\n{'='*60}")
    print(f"  GrandChase AES Key Capture (pareamento por contexto)")
    print(f"{'='*60}")
    print(f"  CIPHER_INIT: 0x{offsets['CIPHER_INIT']:x}")
    print(f"  MODE_INIT:   0x{offsets['MODE_INIT']:x}")
    print(f"  Chaves existentes: {len(existing_keys)} pares")

    device = frida.get_local_device()
    pid = _find_pid(device, PROCESS_NAME) or _find_pid_tasklist(PROCESS_NAME)
    if not pid:
        print(f"\n  [!] {PROCESS_NAME} nao encontrado. Abra o jogo primeiro.")
        sys.exit(1)

    print(f"  PID: {pid}")
    print(f"  Conectando (retry ate 30s)...")

    try:
        session = try_attach(device, pid, timeout=30)
    except Exception as e:
        print(f"\n  [!] Falha ao conectar apos retries: {e}")
        sys.exit(1)
    print(f"  Conectado!")
    print(f"  Instalando hooks em {args.delay}s...")

    js = JS_SRC
    js = js.replace("__DELAY_MS__", str(args.delay * 1000))
    js = js.replace("__CIPHER_INIT_OFF__", hex(offsets["CIPHER_INIT"]))
    js = js.replace("__MODE_INIT_OFF__", hex(offsets["MODE_INIT"]))

    # Teste em tempo real contra KOMs faltantes
    tester = None
    if args.target_koms:
        tester = TargetTester(args.target_koms)
        if tester.pending:
            print(f"  KOMs alvo: {', '.join(sorted(tester.pending.keys()))}")
            print(f"  Cada novo par sera testado contra esses KOMs em tempo real.")
        else:
            print(f"  [!] Nenhum arquivo encontrado nos KOMs alvo.")
            tester = None

    capture = KeyCapture(existing_keys, target_tester=tester)
    log_file = open(CAPTURE_LOG, "a", encoding="utf-8")

    def on_message(message, data):
        if message["type"] == "send":
            capture.handle(message["payload"], log_file)
        elif message["type"] == "error":
            print(f"  [!] JS error: {message.get('description', '')}")

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print(f"\n  Capturando por ate {args.duration}s... (Ctrl+C para parar)")
    if tester and tester.pending:
        print(f"  Entre no jogo (lobby/menu) para carregar: {', '.join(sorted(tester.pending.keys()))}")
    else:
        print(f"  Va ao jogo e abra os KOMs necessarios.")
    print()

    start = time.time()
    try:
        while time.time() - start < args.duration:
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed > 0 and elapsed % 30 == 0:
                np = len(capture.new_pairs)
                cp = len(capture.confirmed_pairs)
                uk = capture.unique_keys
                ui = capture.unique_ivs
                line = f"  [{elapsed}s] keys={uk}  ivs={ui}  pares={cp}  novos={np}"
                if tester:
                    line += f"  | {tester.status_line().strip()}"
                print(line)
    except KeyboardInterrupt:
        print("\n  [*] Interrompido pelo usuario")

    print(capture.summary())

    # Resumo de KOMs alvo
    if tester:
        print()
        if tester.solved:
            print(f"  KOMs RESOLVIDOS: {', '.join(sorted(tester.solved.keys()))}")
        if tester.pending:
            print(f"  KOMs PENDENTES:  {', '.join(sorted(tester.pending.keys()))}")
            print(f"  (as chaves desses KOMs nao foram carregadas nesta sessao)")

    try:
        script.unload()
    except Exception:
        pass
    log_file.close()

    print(f"  Log: {CAPTURE_LOG} ({len(capture.events)} eventos)")

    if args.auto_merge and capture.new_pairs:
        merge_into_algo3(capture.new_pairs)
    elif capture.new_pairs:
        print(f"\n  [*] Use --auto-merge para adicionar automaticamente ao algo3_keys.json")


if __name__ == "__main__":
    main()
