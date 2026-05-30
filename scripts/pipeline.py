#!/usr/bin/env python3
"""
pipeline.py — Pipeline completo: Extrair → Decriptar → Decompilar
===================================================================

Executa os 3 passos offline do toolkit em sequência:
  04_extract_koms.py  → Extrai arquivos dos KOMs
  05_decrypt_all.py   → Decripta Lua/STG
  06_decompile_all.py → Decompila KL bytecode para Lua legível

Para os passos que envolvem Frida (01, 02, 03), use-os separadamente
pois requerem o jogo aberto.

Uso:
  python scripts/pipeline.py                                  # Pipeline completo
  python scripts/pipeline.py --skip-extract                    # Pular extração
  python scripts/pipeline.py --skip-decompile                  # Pular decompilação
  python scripts/pipeline.py --filter Solene                   # Filtrar por nome
  python scripts/pipeline.py --game-dir "C:\\GrandChase"         # Caminho do jogo

Saída:
  output/extracted/   — Arquivos extraídos dos KOMs
  output/decrypted/   — Lua/STG decriptados
  output/decompiled/  — Código Lua legível
"""
import os
import sys
import time
import subprocess
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
OUTPUT_DIR = os.path.join(TOOLKIT_ROOT, "output")


def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def run_step(script_name, extra_args, label):
    """Executa um script do pipeline como subprocesso."""
    script_path = os.path.join(SCRIPT_DIR, script_name)
    cmd = [sys.executable, script_path] + extra_args
    print(f"\n  Executando: {script_name}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"  [!] {script_name} terminou com código {result.returncode}")
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline completo: Extrair → Decriptar → Decompilar",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--game-dir", default=r"C:\Program Files\Epic Games\GrandChaseuVQ2P",
                        help="Pasta de instalação do jogo")
    parser.add_argument("--input", "-i", nargs="*", help="KOMs específicos (default: todos do jogo)")
    parser.add_argument("--filter", help="Filtrar por nome (substring)")
    parser.add_argument("--skip-extract", action="store_true", help="Pular extração de KOMs")
    parser.add_argument("--skip-decrypt", action="store_true", help="Pular decriptação")
    parser.add_argument("--skip-decompile", action="store_true", help="Pular decompilação")
    parser.add_argument("--force", action="store_true", help="Reprocessar tudo")
    parser.add_argument("--debug", action="store_true", help="Modo verboso")
    args = parser.parse_args()

    t0 = time.time()

    extracted_dir = os.path.join(OUTPUT_DIR, "extracted")
    decrypted_dir = os.path.join(OUTPUT_DIR, "decrypted")
    decompiled_dir = os.path.join(OUTPUT_DIR, "decompiled")

    print(f"\n{'='*60}")
    print(f"  GrandChase Toolkit — Pipeline Completo")
    print(f"{'='*60}")

    # ─── Passo 1: Extrair KOMs ────────────────────────────────────
    if not args.skip_extract:
        banner("Passo 1/3: Extraindo KOMs")
        extract_args = ["-o", extracted_dir]
        if args.input:
            extract_args += ["--input"] + args.input
        else:
            extract_args += ["--game-dir", args.game_dir]
        if args.filter:
            extract_args += ["--filter", args.filter]
        if args.debug:
            extract_args.append("--debug")
        run_step("04_extract_koms.py", extract_args, "Extração")
    else:
        print("\n  [*] Extração pulada (--skip-extract)")

    # ─── Passo 2: Decriptar ───────────────────────────────────────
    if not args.skip_decrypt:
        banner("Passo 2/3: Decriptando Lua/STG")
        decrypt_args = ["-i", extracted_dir, "-o", decrypted_dir]
        if args.filter:
            decrypt_args += ["--filter", args.filter]
        if args.force:
            decrypt_args.append("--force")
        run_step("05_decrypt_all.py", decrypt_args, "Decriptação")
    else:
        print("\n  [*] Decriptação pulada (--skip-decrypt)")

    # ─── Passo 3: Decompilar ─────────────────────────────────────
    if not args.skip_decompile:
        banner("Passo 3/3: Decompilando bytecode KL")
        decompile_args = ["-i", decrypted_dir, "-o", decompiled_dir]
        if args.filter:
            decompile_args += ["--filter", args.filter]
        if args.force:
            decompile_args.append("--force")
        run_step("06_decompile_all.py", decompile_args, "Decompilação")
    else:
        print("\n  [*] Decompilação pulada (--skip-decompile)")

    elapsed = time.time() - t0
    banner(f"Pipeline Concluído em {elapsed:.1f}s")
    print(f"  Extraídos:    {extracted_dir}")
    print(f"  Decriptados:  {decrypted_dir}")
    print(f"  Decompilados: {decompiled_dir}")
    print()


if __name__ == "__main__":
    main()
