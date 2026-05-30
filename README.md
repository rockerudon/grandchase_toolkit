# Grand Chase Classic Toolkit

Complete toolkit for extracting, decrypting, and decompiling files from Grand Chase Classic (Epic Games).

## Structure

```
grandchase_toolkit/
├── README.md                  ← This file
├── requirements.txt           ← Python dependencies
├── keys/
│   ├── algo3_keys.json        ← AES-256-CBC keys (accumulates across updates)
│   ├── algo2_table_full.bin   ← Blowfish table (13,790 entries)
│   ├── algo2_table.bin        ← Blowfish table (984 entries, legacy)
│   ├── captured_keys.jsonl    ← Raw keys captured at runtime
│   └── offsets.json           ← Crypto function offsets
├── scripts/
│   ├── 01_dump_exe.py         ← Dump unpacked .exe (Ghidra)
│   ├── 02_find_offsets.py     ← Find offsets after game update
│   ├── 03_capture_keys.py     ← Capture AES keys at runtime
│   ├── 04_extract_koms.py     ← Extract files from KOMs
│   ├── 05_decrypt_all.py      ← Decrypt Lua/STG
│   ├── 06_decompile_all.py    ← Decompile KL → readable Lua
│   └── pipeline.py            ← Full pipeline (04→05→06)
├── extractor/
│   └── kom_crypto.py          ← KOM parsing engine
├── decompiler/
│   └── ljd_decompiler/        ← LJD decompiler (KL bytecode)
├── docs/
│   ├── UPDATE_GUIDE.md        ← How to update offsets/keys
│   ├── KOM_FORMAT.md          ← Documented KOM format
│   └── CRYPTO_PIPELINE.md     ← Encryption pipeline
└── output/
    ├── extracted/             ← Extraction output
    ├── decrypted/             ← Decryption output
    └── decompiled/            ← Decompilation output
```

## Installation

```bash
# 1. Install Python 3.10+
# 2. Install dependencies
pip install -r requirements.txt

# Or with venv:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

### Full Pipeline (offline — no need to have the game running)

```bash
# Extract + Decrypt + Decompile all KOMs
python scripts/pipeline.py

# With a custom game directory
python scripts/pipeline.py --game-dir "C:\Program Files\Epic Games\GrandChaseuVQ2P"

# Decrypt and decompile only (KOMs already extracted)
python scripts/pipeline.py --skip-extract

# Filter by name
python scripts/pipeline.py --filter Solene
```

### Individual Scripts

```bash
# Extract KOMs
python scripts/04_extract_koms.py
python scripts/04_extract_koms.py --input file.kom
python scripts/04_extract_koms.py --list     # List only

# Decrypt Lua/STG
python scripts/05_decrypt_all.py
python scripts/05_decrypt_all.py --algo3-only

# Decompile KL bytecode
python scripts/06_decompile_all.py
python scripts/06_decompile_all.py --filter CharScript
```

## After a Game Update

When the game updates, the crypto function offsets change and new AES keys may
appear. Follow these steps:

```bash
# 1. Launch the game and wait for the login screen

# 2. Find new offsets (automatic via byte signatures)
.venv\Scripts\python.exe scripts/02_find_offsets.py

# 3. Capture new AES keys (run terminal as ADMINISTRATOR, navigate through the game)
.venv\Scripts\python.exe scripts/03_capture_keys.py --auto-merge

# 4. Run the pipeline normally
.venv\Scripts\python.exe scripts/pipeline.py --force
```

For full details about the update process, see `docs/UPDATE_GUIDE.md`.

## Encryption Algorithms

Grand Chase uses 3 algorithms to protect the files inside the KOMs:

| Algorithm | Encryption | Files |
|-----------|-------------|----------|
| **Algo 0** | zlib only (no encryption) | Most resources |
| **Algo 2** | Blowfish-ECB → zlib | Assets (.frm, .dds, .p3m) |
| **Algo 3** | AES-256-CBC → zlib → Blowfish-ECB | Lua/STG |

For technical details, see `docs/CRYPTO_PIPELINE.md`.

## Keys and Tables

### algo3_keys.json
Database of (key, iv) pairs for AES-256-CBC. Accumulates across updates.
Captured via Frida at runtime (script 03).

### algo2_table_full.bin
Value table for Blowfish key derivation.
13,790 entries × 5 × int64 = 551,600 bytes.
Derivation: `sum(5_values)` → `str(total).encode('ascii')` → SHA-256 → 32-byte key.

### offsets.json
RVAs of the crypto functions in GrandChase.exe (relative to the module base).
Includes byte signatures for automatic lookup and offset history.

## Notes

- **Frida** is only required for scripts 01, 02 and 03 (runtime hooks).
  Scripts 04, 05 and 06 work 100% offline.
- **Administrator**: Script 03 (capture_keys) needs to run in a terminal with
  Administrator privileges so Frida can inject into the protected process.
- **Themida**: The game uses Themida for protection. Script 03 uses automatic retry
  and setTimeout in JS to wait for the unpacking.
- **venv**: Always use `.venv\Scripts\python.exe` to ensure the correct 64-bit
  Python with a compatible Frida.
- The LJD decompiler uses a custom bytecode format (KL, not standard LuaJIT)
  with 97 remapped opcodes.

## Documentation

- `docs/UPDATE_GUIDE.md` — Complete guide for updating offsets/keys after game patches
- `docs/KOM_FORMAT.md` — Detailed KOM format specification
- `docs/CRYPTO_PIPELINE.md` — Encryption pipeline technical details

## Disclaimer

This tool is for educational and research purposes only. Use at your own risk.

## Support the Project

If this project was useful to you, consider supporting its development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/rockmizx)

Or visit directly: https://buymeacoffee.com/rockmizx

---

**Made with care for the Grand Chase Classic community**
