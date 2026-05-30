#!/usr/bin/env python3
"""
06_decompile_all.py — Decompila bytecode KL para Lua legível
=============================================================

Processa arquivos KL bytecode (\\x1bKL\\x84) decriptados pelo 05_decrypt_all.py
e gera código Lua legível usando o decompilador LJD.

Pipeline de decompilação (3 níveis de fallback):
  Level 0 (completo): parse → AST → validate → mutator → slots →
                       unwarper → mark_local_definitions → primary_pass → write
  Level 1 (sem unwarper): parse → AST → mutator → slots → write
  Level 2 (mínimo): parse → AST → mutator → write

STG:
  .stg UTF-16-LE com BOM: convertido para UTF-8
  .kstg: copiado como está (binário de mapa)

Uso:
  python scripts/06_decompile_all.py                       # Decompila tudo
  python scripts/06_decompile_all.py --input pasta/        # Pasta customizada
  python scripts/06_decompile_all.py --filter Solene       # Filtrar por nome

Saída:
  output/decompiled/  — código Lua legível + STG em UTF-8
"""
import os
import sys
import io
import time
import threading
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))

DEFAULT_INPUT = os.path.join(TOOLKIT_ROOT, "output", "decrypted")
DEFAULT_OUTPUT = os.path.join(TOOLKIT_ROOT, "output", "decompiled")

# Adicionar LJD ao path
LJD_PATH = os.path.join(TOOLKIT_ROOT, "decompiler", "ljd_decompiler")
sys.path.insert(0, LJD_PATH)

# Limites de segurança
sys.setrecursionlimit(20000)
DECOMPILE_TIMEOUT = 60  # segundos base por arquivo
DECOMPILE_TIMEOUT_PER_MB = 60  # segundos adicionais por MB

KL_MAGIC = b'\x1bKL\x84'
LJ_MAGIC = b'\x1bLJ'
STG_BOM = b'\xff\xfe'


# ==========================================================================
# LJD Decompiler
# ==========================================================================
_ljd_loaded = False


def _ensure_ljd():
    global _ljd_loaded
    if _ljd_loaded:
        return True
    try:
        import ljd.rawdump.parser
        _ljd_loaded = True
        return True
    except ImportError:
        print("[!] LJD decompiler não encontrado!")
        print(f"    Verifique se existe: {LJD_PATH}")
        return False


def decompile_bytecode(source_bytes, source_name="<input>"):
    """
    Decompila bytecode KL usando LJD com 3 níveis de fallback.
    Retorna (level, lua_source) ou None.
    """
    if not _ensure_ljd():
        return None

    import ljd.rawdump.parser
    import ljd.ast.builder
    import ljd.ast.validator
    import ljd.ast.mutator
    import ljd.ast.locals
    import ljd.ast.slotworks
    import ljd.ast.unwarper
    import ljd.ast.slotrenamer
    import ljd.ast.dce
    import ljd.lua.writer
    import ljd.lua.postprocess

    # Parse bytecode (precisa de arquivo temporário)
    import tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.lua')
    try:
        tmp.write(source_bytes)
        tmp.close()
        header, prototype = ljd.rawdump.parser.parse(tmp.name)
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    if not prototype:
        return None

    # Level 0: Pipeline completo
    try:
        ast = ljd.ast.builder.build(prototype)
        if ast is None:
            raise RuntimeError("AST build failed")
        ljd.ast.validator.validate(ast, warped=True)
        ljd.ast.mutator.pre_pass(ast)
        ljd.ast.locals.mark_locals(ast)
        ljd.ast.slotworks.eliminate_temporary(ast)
        ljd.ast.unwarper.unwarp(ast)
        try:
            ljd.ast.locals.mark_local_definitions(ast)
        except (AttributeError, KeyError, IndexError):
            pass
        try:
            ljd.ast.mutator.primary_pass(ast)
        except (AttributeError, KeyError, IndexError, AssertionError):
            pass
        try:
            ljd.ast.validator.validate(ast, warped=False)
        except (AssertionError, Exception):
            pass
        ljd.ast.slotrenamer.rename_slots(ast)
        try:
            ljd.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        buf = io.StringIO()
        ljd.lua.writer.write(buf, ast)
        source = ljd.lua.postprocess.postprocess(buf.getvalue())
        return (0, source)
    except (Exception, RecursionError):
        pass

    # Level 1: Sem unwarper
    try:
        ast = ljd.ast.builder.build(prototype)
        ljd.ast.validator.validate(ast, warped=True)
        ljd.ast.mutator.pre_pass(ast)
        ljd.ast.locals.mark_locals(ast)
        ljd.ast.slotworks.eliminate_temporary(ast)
        ljd.ast.slotrenamer.rename_slots(ast)
        try:
            ljd.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        buf = io.StringIO()
        ljd.lua.writer.write(buf, ast)
        source = ljd.lua.postprocess.postprocess(buf.getvalue())
        return (1, source)
    except (Exception, RecursionError):
        pass

    # Level 2: Mínimo
    try:
        ast = ljd.ast.builder.build(prototype)
        ljd.ast.mutator.pre_pass(ast)
        ljd.ast.slotrenamer.rename_slots(ast)
        try:
            ljd.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        buf = io.StringIO()
        ljd.lua.writer.write(buf, ast)
        source = ljd.lua.postprocess.postprocess(buf.getvalue())
        return (2, source)
    except (Exception, RecursionError):
        pass

    return None


def decompile_safe(source_bytes, source_name="<input>"):
    """
    Wrapper com thread separada (64MB stack) + timeout.
    Evita crash por stack overflow em ASTs profundas.
    """
    result = [None]

    def worker():
        try:
            result[0] = decompile_bytecode(source_bytes, source_name)
        except BaseException:
            pass

    try:
        threading.stack_size(64 * 1024 * 1024)
    except (ValueError, RuntimeError):
        pass

    size_mb = len(source_bytes) / (1024 * 1024)
    timeout = DECOMPILE_TIMEOUT + size_mb * DECOMPILE_TIMEOUT_PER_MB

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout=timeout)

    try:
        threading.stack_size(0)
    except (ValueError, RuntimeError):
        pass

    if t.is_alive():
        return None
    return result[0]


# ==========================================================================
# STG Processing
# ==========================================================================
def convert_stg_to_utf8(data):
    """Converte STG UTF-16-LE (com BOM) para UTF-8."""
    if data[:2] == STG_BOM:
        try:
            text = data[2:].decode("utf-16-le")
            return text.encode("utf-8")
        except Exception:
            pass
    return data


# ==========================================================================
# Main Processing
# ==========================================================================
def process_directory(input_dir, output_dir, name_filter=None, force=False):
    """Processa todos os arquivos decriptados."""
    stats = {"total": 0, "ok": 0, "skipped": 0, "failed": 0,
             "level0": 0, "level1": 0, "level2": 0,
             "stg": 0, "copied": 0}
    failed_files = []

    if not os.path.isdir(input_dir):
        print(f"[!] Pasta não encontrada: {input_dir}")
        return stats

    # Coletar arquivos
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
        print("[!] Nenhum arquivo encontrado.")
        return stats

    stats["total"] = len(all_files)
    print(f"\n  Arquivos: {len(all_files)}")
    print(f"  Entrada: {input_dir}")
    print(f"  Saída: {output_dir}")

    os.makedirs(output_dir, exist_ok=True)
    t0 = time.time()

    for i, (path, rel, ext) in enumerate(all_files, 1):
        out_path = os.path.join(output_dir, rel)
        out_dir = os.path.dirname(out_path)
        os.makedirs(out_dir, exist_ok=True)

        # Verificar se já existe
        if os.path.isfile(out_path) and not force:
            stats["skipped"] += 1
            continue

        with open(path, "rb") as f:
            data = f.read()

        # .kstg — copiar como está
        if ext == '.kstg':
            with open(out_path, "wb") as f:
                f.write(data)
            stats["copied"] += 1
            stats["ok"] += 1
            continue

        # .stg — converter UTF-16 → UTF-8
        if ext == '.stg':
            if data[:2] == STG_BOM:
                out_data = convert_stg_to_utf8(data)
            else:
                out_data = data
            with open(out_path, "wb") as f:
                f.write(out_data)
            stats["stg"] += 1
            stats["ok"] += 1
            continue

        # .lua — decompile KL bytecode
        if data[:4] == KL_MAGIC or data[:3] == LJ_MAGIC:
            result = decompile_safe(data, rel)
            if result:
                level, source = result
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(source)
                    if not source.endswith('\n'):
                        f.write('\n')
                stats["ok"] += 1
                if level == 0:
                    stats["level0"] += 1
                elif level == 1:
                    stats["level1"] += 1
                else:
                    stats["level2"] += 1
            else:
                # Falha na decompilação — salvar bytecode raw
                raw_path = out_path + ".kl"
                with open(raw_path, "wb") as f:
                    f.write(data)
                stats["failed"] += 1
                failed_files.append(rel)
        else:
            # Não é KL — copiar como está
            with open(out_path, "wb") as f:
                f.write(data)
            stats["copied"] += 1
            stats["ok"] += 1

        if (i % 20 == 0) or i == len(all_files):
            print(f"\r  [{i}/{len(all_files)}] {stats['ok']} OK, {stats['failed']} falhas...", end="", flush=True)

    elapsed = time.time() - t0
    print(f"\r  {'─'*50}")
    print(f"  Concluído em {elapsed:.1f}s")
    print(f"  Total: {stats['ok']}/{stats['total']} processados")
    print(f"    L0 (completo):    {stats['level0']}")
    print(f"    L1 (sem unwarp):  {stats['level1']}")
    print(f"    L2 (mínimo):      {stats['level2']}")
    print(f"    STG convertidos:  {stats['stg']}")
    print(f"    Copiados:         {stats['copied']}")
    print(f"    Pulados:          {stats['skipped']}")
    if stats["failed"]:
        print(f"    Falhas:           {stats['failed']}")
        for f in failed_files[:10]:
            print(f"      - {f}")
        if len(failed_files) > 10:
            print(f"      ... e mais {len(failed_files) - 10}")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Decompila bytecode KL para Lua legível")
    parser.add_argument("--input", "-i", default=DEFAULT_INPUT, help="Pasta com arquivos decriptados")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="Pasta de saída")
    parser.add_argument("--filter", help="Filtrar por nome (substring)")
    parser.add_argument("--force", action="store_true", help="Reprocessar arquivos existentes")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  GrandChase Decompiler (LJD)")
    print(f"{'='*60}")

    if not _ensure_ljd():
        print("\n[!] Copie a pasta ljd_decompiler para decompiler/ljd_decompiler/")
        sys.exit(1)

    process_directory(args.input, args.output, args.filter, args.force)
    print()


if __name__ == "__main__":
    main()
