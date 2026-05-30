#!/usr/bin/env python3
"""
05_decrypt_all.py — Decripta Lua e STG extraídos dos KOMs
==========================================================

Pipeline de decriptação:
  Algorithm 2 (Blowfish-ECB):
    encrypted → BF-ECB decrypt → zlib → original
    Chave: tabela de valores → sum → str(total).encode('ascii') → SHA256 → full 32 bytes

  Algorithm 3 (AES-256-CBC + Blowfish-ECB):
    encrypted → AES-256-CBC decrypt(key, iv) → zlib → BF-ECB decrypt → KL bytecode
    Chaves AES: capturadas via Frida (algo3_keys.json)
    Chave BF: mesma derivação do Algo2

  STG (Blowfish-ECB direto):
    encrypted → BF-ECB decrypt(key_32B) → UTF-16-LE text
    Chaves: capturadas via stg_keycapture ou cross-key brute-force

Uso:
  python scripts/05_decrypt_all.py                        # Decripta tudo
  python scripts/05_decrypt_all.py --input pasta/         # Pasta customizada
  python scripts/05_decrypt_all.py --algo3-only           # Apenas algo3
  python scripts/05_decrypt_all.py --filter Solene        # Filtrar por nome

Saída:
  output/decrypted/  — arquivos decriptados (.lua = KL bytecode, .stg = texto)
"""
import os
import sys
import struct
import hashlib
import zlib
import json
import time
import argparse
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
KEYS_DIR = os.path.join(TOOLKIT_ROOT, "keys")

DEFAULT_INPUT = os.path.join(TOOLKIT_ROOT, "output", "extracted")
DEFAULT_OUTPUT = os.path.join(TOOLKIT_ROOT, "output", "decrypted")

ALGO3_KEYS_PATH = os.path.join(KEYS_DIR, "algo3_keys.json")
ALGO2_TABLE_PATH = os.path.join(KEYS_DIR, "algo2_table_full.bin")
ALGO2_TABLE_FALLBACK = os.path.join(KEYS_DIR, "algo2_table.bin")

KL_MAGIC = b'\x1bKL\x84'
LJ_MAGIC = b'\x1bLJ'
ZLIB_PREFIXES = [b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda']
STG_BOM = b'\xff\xfe'

try:
    from Crypto.Cipher import Blowfish, AES
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    print("[!] pycryptodome não instalado. Rode: pip install pycryptodome")


# ==========================================================================
# Blowfish Key Derivation (Algorithm 2)
# ==========================================================================
_bf_keys_cache = None


def load_bf_keys():
    """Carrega tabela de valores e pré-calcula chaves Blowfish (SHA256)."""
    global _bf_keys_cache
    if _bf_keys_cache is not None:
        return _bf_keys_cache

    table_path = ALGO2_TABLE_PATH
    if not os.path.isfile(table_path):
        table_path = ALGO2_TABLE_FALLBACK
    if not os.path.isfile(table_path):
        print(f"[!] Tabela BF não encontrada: {ALGO2_TABLE_PATH}")
        _bf_keys_cache = []
        return _bf_keys_cache

    with open(table_path, "rb") as f:
        table_data = f.read()

    count = len(table_data) // 0x28  # 40 bytes por entrada (5 × int64)
    keys = []
    for i in range(count):
        vals = struct.unpack_from('<5q', table_data, i * 0x28)
        total = sum(vals)
        if total < 0:
            total = total & 0xFFFFFFFFFFFFFFFF
        # Derivação correta: str(total) em ASCII → SHA256 → digest completo (32 bytes)
        key = hashlib.sha256(str(total).encode('ascii')).digest()
        keys.append(key)

    _bf_keys_cache = keys
    print(f"  Tabela BF: {count} entradas carregadas de {os.path.basename(table_path)}")
    return keys


def decrypt_bf(data, recent_indices=None):
    """
    Tenta decriptar com Blowfish-ECB (brute-force).
    Otimização: testa apenas os primeiros 8 bytes antes de decriptar tudo.
    Retorna (plaintext, key_index) ou (None, -1).
    """
    if not CRYPTO_OK:
        return None, -1

    keys = load_bf_keys()
    if not keys:
        return None, -1

    full_len = len(data) - (len(data) % 8)
    if full_len < 8:
        return None, -1

    tail = data[full_len:]
    first_block = data[:8]

    def _is_magic(dec8):
        """Quick check: primeiros bytes decriptados batem com magic conhecido."""
        if dec8[:4] == KL_MAGIC or dec8[:3] == LJ_MAGIC:
            return True
        if dec8[:2] == STG_BOM:
            return True
        if dec8[:2] in (b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda'):
            return True
        return False

    def _full_decrypt(idx):
        """Decripta tudo e valida."""
        cipher = Blowfish.new(keys[idx], Blowfish.MODE_ECB)
        dec = cipher.decrypt(data[:full_len]) + tail
        if dec[:4] == KL_MAGIC or dec[:3] == LJ_MAGIC:
            return dec
        if dec[:2] == STG_BOM:
            return dec
        if dec[:2] in (b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda'):
            try:
                zlib.decompress(dec)
                return dec
            except zlib.error:
                return None
        return None

    # Tentar índices recentes primeiro (cache per-KOM)
    if recent_indices:
        for idx in recent_indices:
            if idx >= len(keys):
                continue
            try:
                cipher = Blowfish.new(keys[idx], Blowfish.MODE_ECB)
                dec8 = cipher.decrypt(first_block)
                if _is_magic(dec8):
                    result = _full_decrypt(idx)
                    if result is not None:
                        return result, idx
            except Exception:
                continue

    # Brute-force: testar apenas 8 bytes, decriptar tudo só no match
    tried = recent_indices or set()
    for idx in range(len(keys)):
        if idx in tried:
            continue
        try:
            cipher = Blowfish.new(keys[idx], Blowfish.MODE_ECB)
            dec8 = cipher.decrypt(first_block)
            if _is_magic(dec8):
                result = _full_decrypt(idx)
                if result is not None:
                    return result, idx
        except Exception:
            continue

    return None, -1


# ==========================================================================
# AES-256-CBC (Algorithm 3)
# ==========================================================================
_algo3_pairs = None


def load_algo3_keys():
    """Carrega pares (key, iv) do algo3_keys.json."""
    global _algo3_pairs
    if _algo3_pairs is not None:
        return _algo3_pairs

    try:
        with open(ALGO3_KEYS_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        _algo3_pairs = [
            (bytes.fromhex(p["key"]), bytes.fromhex(p["iv"]))
            for p in data.get("pairs", [])
        ]
    except FileNotFoundError:
        _algo3_pairs = []
        print(f"[!] algo3_keys.json não encontrado: {ALGO3_KEYS_PATH}")

    return _algo3_pairs


def decrypt_aes_cbc(data, cached_pair=None):
    """
    Decripta AES-256-CBC. Testa pares até encontrar magic zlib no plaintext.
    Retorna (plaintext_zlib, (key, iv)) ou (None, None).
    """
    if not CRYPTO_OK or len(data) < 16:
        return None, None

    pairs = [cached_pair] if cached_pair else load_algo3_keys()

    for key, iv in pairs:
        if not key or not iv:
            continue
        try:
            # Quick check: decrypt first block and XOR with IV
            ecb = AES.new(key, AES.MODE_ECB)
            dec_block = ecb.decrypt(data[:16])
            plain0 = bytes(a ^ b for a, b in zip(dec_block, iv))
            if plain0[:2] not in [b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda']:
                continue
            # Full decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            full_dec = cipher.decrypt(data)
            try:
                zlib.decompress(full_dec)
                return full_dec, (key, iv)
            except zlib.error:
                # Tentar com strip PKCS#7
                pad_len = full_dec[-1]
                if 1 <= pad_len <= 16 and all(b == pad_len for b in full_dec[-pad_len:]):
                    try:
                        zlib.decompress(full_dec[:-pad_len])
                        return full_dec[:-pad_len], (key, iv)
                    except Exception:
                        pass
        except Exception:
            continue

    return None, None


def decrypt_algo3_file(data, cached_aes_pair=None, recent_bf_indices=None):
    """
    Pipeline completo Algorithm 3:
      AES-CBC → zlib decompress → Blowfish-ECB → KL bytecode

    Retorna (plaintext_kl, aes_pair, bf_idx) ou (None, None, -1).
    """
    # Passo 1: AES-CBC
    aes_dec, aes_pair = decrypt_aes_cbc(data, cached_aes_pair)
    if aes_dec is None:
        return None, None, -1

    # Passo 2: zlib decompress
    try:
        inner = zlib.decompress(aes_dec)
    except zlib.error:
        # Tentar strip padding
        pad_len = aes_dec[-1]
        if 1 <= pad_len <= 16:
            try:
                inner = zlib.decompress(aes_dec[:-pad_len])
            except Exception:
                return None, aes_pair, -1
        else:
            return None, aes_pair, -1

    # Verificar se já é KL bytecode (sem camada BF)
    if inner[:4] == KL_MAGIC or inner[:3] == LJ_MAGIC:
        return inner, aes_pair, 0

    # Passo 3: Blowfish-ECB
    bf_dec, bf_idx = decrypt_bf(inner, recent_bf_indices)
    if bf_dec is not None:
        return bf_dec, aes_pair, bf_idx

    return None, aes_pair, -1


# ==========================================================================
# STG Decryption
# ==========================================================================
def decrypt_stg(data, stg_keys):
    """
    Decripta STG com Blowfish-ECB usando chaves bruteforce.
    stg_keys = [(key_hex, key_bytes), ...]
    Retorna (plaintext, key_hex) ou (None, None).
    """
    if not CRYPTO_OK or len(data) < 8:
        return None, None

    for key_hex, key_bytes in stg_keys:
        try:
            cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
            first = cipher.decrypt(data[:8])
            if first[:2] != STG_BOM:
                continue
            # Decrypt tudo
            aligned = (len(data) // 8) * 8
            dec = cipher.decrypt(data[:aligned]) + data[aligned:]
            # Verificar UTF-16
            try:
                text = dec[2:].decode("utf-16-le", errors="replace")[:100]
                printable = sum(1 for c in text if c.isprintable() or c in '\t\n\r')
                if printable / max(1, len(text)) > 0.7:
                    return dec, key_hex
            except Exception:
                continue
        except Exception:
            continue

    return None, None


# ==========================================================================
# File Detection
# ==========================================================================
def detect_file_type(data):
    """Detecta tipo do arquivo pelos magic bytes."""
    if not data:
        return "empty"
    if data[:4] == KL_MAGIC:
        return "kl_bytecode"
    if data[:3] == LJ_MAGIC:
        return "lj_bytecode"
    if data[:2] in [b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda']:
        return "zlib"
    if data[:2] == STG_BOM:
        return "stg_plaintext"
    # Check if printable text
    sample = data[:64]
    if all(b < 0x80 and (b >= 0x20 or b in (0x09, 0x0A, 0x0D)) for b in sample):
        return "plaintext"
    return "encrypted"


# ==========================================================================
# Main Processing
# ==========================================================================
def process_directory(input_dir, output_dir, algo3_only=False, name_filter=None, force=False):
    """Processa todos os arquivos extraídos de KOMs."""
    stats = {"total": 0, "decrypted": 0, "skipped": 0, "failed": 0,
             "algo2_ok": 0, "algo3_ok": 0, "stg_ok": 0, "already_plain": 0}

    if not os.path.isdir(input_dir):
        print(f"[!] Pasta de entrada não encontrada: {input_dir}")
        return stats

    # Coletar todos os arquivos
    all_files = []
    for root, _, files in os.walk(input_dir):
        for f in sorted(files):
            ext = os.path.splitext(f)[1].lower()
            if ext in ('.lua', '.stg', '.kstg'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, input_dir)
                if name_filter and name_filter.lower() not in rel.lower():
                    continue
                all_files.append((path, rel, ext))

    if not all_files:
        print("[!] Nenhum arquivo .lua/.stg/.kstg encontrado.")
        return stats

    stats["total"] = len(all_files)
    print(f"\n  Arquivos: {len(all_files)} (.lua/.stg/.kstg)")
    print(f"  Entrada: {input_dir}")
    print(f"  Saída: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    # Cache per-KOM
    cached_aes_pair = None
    cached_bf_indices = set()
    current_kom = None

    # Carregar chaves STG se disponíveis
    stg_keys_path = os.path.join(KEYS_DIR, "stg_keys.json")
    stg_keys = []
    if os.path.isfile(stg_keys_path):
        with open(stg_keys_path, "r") as f:
            sk = json.load(f)
        unique = set(sk.values()) if isinstance(sk, dict) else set()
        stg_keys = [(kh, bytes.fromhex(kh)) for kh in unique]
        print(f"  Chaves STG: {len(stg_keys)} únicas")

    # Processar
    t0 = time.time()
    for i, (path, rel, ext) in enumerate(all_files, 1):
        # Determinar KOM de origem
        parts = rel.replace("\\", "/").split("/")
        kom_name = parts[0] if parts else ""
        if kom_name != current_kom:
            current_kom = kom_name
            cached_aes_pair = None
            cached_bf_indices = set()

        # Output path
        out_path = os.path.join(output_dir, rel)
        out_dir = os.path.dirname(out_path)
        os.makedirs(out_dir, exist_ok=True)

        # Verificar se já decriptado
        if os.path.isfile(out_path) and not force:
            stats["skipped"] += 1
            continue

        # Ler arquivo
        with open(path, "rb") as f:
            data = f.read()

        ftype = detect_file_type(data)

        # Já plaintext/bytecode
        if ftype in ("kl_bytecode", "lj_bytecode", "plaintext", "stg_plaintext"):
            with open(out_path, "wb") as f:
                f.write(data)
            stats["already_plain"] += 1
            stats["decrypted"] += 1
            continue

        # .kstg — binário de mapa, copiar como está
        if ext == '.kstg':
            with open(out_path, "wb") as f:
                f.write(data)
            stats["already_plain"] += 1
            stats["decrypted"] += 1
            continue

        # ── Blowfish-ECB (cobre Algo2, Algo3 pós-extração, e STG) ──
        # O extrator (04_extract_koms.py/kom_crypto.py) já faz AES+zlib
        # para Algo3. Os arquivos aqui precisam apenas de BF-ECB.
        bf_dec, bf_idx = decrypt_bf(data, cached_bf_indices)
        if bf_dec is not None:
            cached_bf_indices.add(bf_idx)

            if bf_dec[:4] == KL_MAGIC or bf_dec[:3] == LJ_MAGIC:
                # BF → KL bytecode (Algo2 ou Algo3 pós-AES-zlib)
                with open(out_path, "wb") as f:
                    f.write(bf_dec)
                stats["algo2_ok"] += 1
                stats["decrypted"] += 1
                if i % 50 == 0 or i == len(all_files):
                    print(f"\r  [{i}/{len(all_files)}] {stats['decrypted']} OK...", end="", flush=True)
                continue

            if bf_dec[:2] == STG_BOM:
                # BF → STG plaintext
                with open(out_path, "wb") as f:
                    f.write(bf_dec)
                stats["stg_ok"] += 1
                stats["decrypted"] += 1
                continue

            if bf_dec[:2] in (b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda'):
                # BF → zlib → plaintext (Algo2 clássico)
                try:
                    plain = zlib.decompress(bf_dec)
                    with open(out_path, "wb") as f:
                        f.write(plain)
                    stats["algo2_ok"] += 1
                    stats["decrypted"] += 1
                    continue
                except zlib.error:
                    pass

        # ── AES-256-CBC pipeline (caso raro: dados ainda com AES) ──
        if ext == '.lua' and len(data) >= 16 and len(data) % 16 == 0:
            kl_data, aes_pair, bf_idx2 = decrypt_algo3_file(data, cached_aes_pair, cached_bf_indices)
            if kl_data is not None:
                with open(out_path, "wb") as f:
                    f.write(kl_data)
                if aes_pair:
                    cached_aes_pair = aes_pair
                if bf_idx2 > 0:
                    cached_bf_indices.add(bf_idx2)
                stats["algo3_ok"] += 1
                stats["decrypted"] += 1
                continue

        # ── STG com chaves específicas capturadas ──
        if ext == '.stg' and stg_keys:
            dec, key_hex = decrypt_stg(data, stg_keys)
            if dec:
                with open(out_path, "wb") as f:
                    f.write(dec)
                stats["stg_ok"] += 1
                stats["decrypted"] += 1
                continue

        # ── Último recurso: zlib puro (algo0) ──
        try:
            plain = zlib.decompress(data)
            with open(out_path, "wb") as f:
                f.write(plain)
            stats["decrypted"] += 1
            continue
        except Exception:
            pass

        stats["failed"] += 1

    elapsed = time.time() - t0
    print(f"\r  {'-'*50}")
    print(f"  Concluído em {elapsed:.1f}s")
    print(f"  Total: {stats['decrypted']}/{stats['total']} decriptados")
    print(f"    Algo2 (BF):   {stats['algo2_ok']}")
    print(f"    Algo3 (AES):  {stats['algo3_ok']}")
    print(f"    STG:          {stats['stg_ok']}")
    print(f"    Plaintext:    {stats['already_plain']}")
    print(f"    Pulados:      {stats['skipped']}")
    if stats["failed"]:
        print(f"    Falhas:       {stats['failed']}")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Decripta Lua/STG extraídos dos KOMs")
    parser.add_argument("--input", "-i", default=DEFAULT_INPUT, help="Pasta com arquivos extraídos")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="Pasta de saída")
    parser.add_argument("--algo3-only", action="store_true", help="Apenas Algorithm 3 (AES)")
    parser.add_argument("--filter", help="Filtrar por nome (substring)")
    parser.add_argument("--force", action="store_true", help="Reprocessar arquivos já decriptados")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  GrandChase Decryptor")
    print(f"{'='*60}")

    process_directory(args.input, args.output, args.algo3_only, args.filter, args.force)
    print()


if __name__ == "__main__":
    main()
