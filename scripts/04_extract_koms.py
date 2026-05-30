#!/usr/bin/env python3
"""
04_extract_koms.py — Extrai todos os arquivos .kom do GrandChase
================================================================

Suporta todos os formatos KOM:
  - KOG V0.1 a V1.0
  - GCM V0.1 a V0.6
  - Algorithm 0 (zlib), Algorithm 2 (Blowfish), Algorithm 3 (AES-256-CBC)

Uso:
  python scripts/04_extract_koms.py                              # Extrai todos os KOMs do jogo
  python scripts/04_extract_koms.py --game-dir "C:\\GrandChase"    # Caminho customizado
  python scripts/04_extract_koms.py --input arquivo.kom           # Um KOM específico
  python scripts/04_extract_koms.py --input pasta_de_koms/        # Pasta com KOMs
  python scripts/04_extract_koms.py --list                        # Apenas listar conteúdo

Saída:
  output/extracted/<nome_do_kom>/  — arquivos extraídos
"""
import os
import sys
import glob
import time
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))

# Adicionar extractor ao path
sys.path.insert(0, os.path.join(TOOLKIT_ROOT, "extractor"))

DEFAULT_OUTPUT = os.path.join(TOOLKIT_ROOT, "output", "extracted")
DEFAULT_GAME_DIR = r"C:\Program Files\Epic Games\GrandChaseuVQ2P"

# Pastas conhecidas com KOMs
KOM_FOLDERS = [
    "Resource", "Character", "Stage", "Sound",
    "ResSet", "Texture", "Item", "Model",
    "Motion", "Dungeon", "anim", "particle",
    "Fan_Map", "Event_Resource", "UI", "AI",
]


def find_koms(paths):
    """Expande caminhos em lista de arquivos .kom."""
    result = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                for f in sorted(files):
                    if f.lower().endswith(".kom"):
                        result.append(os.path.join(root, f))
        elif "*" in p or "?" in p:
            result.extend(sorted(glob.glob(p, recursive=True)))
        elif os.path.isfile(p):
            result.append(p)
        else:
            print(f"[AVISO] Caminho não encontrado: {p}")
    return result


def find_game_koms(game_dir):
    """Encontra todos os KOMs na instalação do jogo (scan recursivo completo)."""
    koms = []
    for root, _, files in os.walk(game_dir):
        for f in sorted(files):
            if f.lower().endswith(".kom"):
                koms.append(os.path.join(root, f))
    return koms


def extract_kom(kom_path, output_dir, debug=False, list_only=False):
    """Extrai um arquivo .kom."""
    from kom_crypto import KomArchive

    stats = {"total": 0, "ok": 0, "fail": 0}

    if not os.path.isfile(kom_path):
        print(f"  [ERRO] Arquivo não encontrado: {kom_path}")
        return stats

    basename = os.path.basename(kom_path)
    size = os.path.getsize(kom_path)

    archive = KomArchive(debug=debug)
    try:
        archive.read_from_file(kom_path)
    except Exception as e:
        print(f"  [ERRO] Falha ao ler {basename}: {e}")
        return stats

    entries = archive.entries
    stats["total"] = len(entries)
    ver = f"V{archive.version}" if archive.version else "?"
    flavor = archive.massfile_flavor

    if list_only:
        print(f"\n  {basename} ({flavor} {ver}) — {len(entries)} entradas, {size:,} bytes")
        for entry in entries:
            name = entry.get("name", "?")
            data = entry.get("data")
            data_size = len(data) if data else 0
            print(f"    {name:<50} {data_size:>10,} bytes")
        return stats

    # Extrair
    kom_name = os.path.splitext(basename)[0]
    out_dir = os.path.join(output_dir, kom_name)
    os.makedirs(out_dir, exist_ok=True)

    for entry in entries:
        name = entry.get("name")
        data = entry.get("data")
        if not name or data is None:
            stats["fail"] += 1
            continue

        safe_name = name.replace("\\", "/").lstrip("/")
        out_path = os.path.join(out_dir, safe_name)
        out_parent = os.path.dirname(out_path)
        if out_parent:
            os.makedirs(out_parent, exist_ok=True)
        try:
            with open(out_path, "wb") as f:
                f.write(data)
            stats["ok"] += 1
        except Exception as e:
            print(f"    [ERRO] {name}: {e}")
            stats["fail"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Extrai arquivos .kom do GrandChase",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", "-i", nargs="*", default=None,
                        help="Arquivo(s) .kom ou pasta (default: detectar do jogo)")
    parser.add_argument("--game-dir", default=DEFAULT_GAME_DIR,
                        help=f"Pasta do jogo (default: {DEFAULT_GAME_DIR})")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help=f"Pasta de saída (default: output/extracted/)")
    parser.add_argument("--list", action="store_true", help="Apenas listar conteúdo")
    parser.add_argument("--debug", action="store_true", help="Modo verboso")
    parser.add_argument("--filter", help="Filtrar KOMs por nome (substring)")
    args = parser.parse_args()

    # Encontrar KOMs
    if args.input:
        koms = find_koms(args.input)
    else:
        if not os.path.isdir(args.game_dir):
            print(f"[!] Pasta do jogo não encontrada: {args.game_dir}")
            print(f"    Use --game-dir ou --input para especificar a localização.")
            sys.exit(1)
        koms = find_game_koms(args.game_dir)

    if args.filter:
        koms = [k for k in koms if args.filter.lower() in os.path.basename(k).lower()]

    if not koms:
        print("[!] Nenhum arquivo .kom encontrado.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  KOM Extractor")
    print(f"{'='*60}")
    print(f"  KOMs encontrados: {len(koms)}")
    if not args.list:
        print(f"  Saída: {args.output}")

    t0 = time.time()
    total = {"total": 0, "ok": 0, "fail": 0}

    for i, kom in enumerate(koms, 1):
        basename = os.path.basename(kom)
        if not args.list:
            print(f"\n  [{i}/{len(koms)}] {basename}...", end="", flush=True)

        stats = extract_kom(kom, args.output, debug=args.debug, list_only=args.list)
        total["total"] += stats["total"]
        total["ok"] += stats["ok"]
        total["fail"] += stats["fail"]

        if not args.list:
            if stats["fail"] == 0:
                print(f" {stats['ok']} arquivos OK")
            else:
                print(f" {stats['ok']} OK, {stats['fail']} falhas")

    elapsed = time.time() - t0
    print(f"\n{'='*60}")
    print(f"  Concluído em {elapsed:.1f}s")
    print(f"  Total: {total['ok']}/{total['total']} extraídos", end="")
    if total["fail"]:
        print(f", {total['fail']} falhas", end="")
    print(f"\n{'='*60}")


if __name__ == "__main__":
    main()
