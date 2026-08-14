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
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Detecção flexível do TOOLKIT_ROOT e PROJECT_ROOT
if os.path.basename(os.path.dirname(SCRIPT_DIR)) == 'toolkit':
    TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
    PROJECT_ROOT = os.path.normpath(os.path.join(TOOLKIT_ROOT, ".."))
else:
    TOOLKIT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
    PROJECT_ROOT = TOOLKIT_ROOT

DEFAULT_INPUT = os.path.join(PROJECT_ROOT, "output", "decrypted")
DEFAULT_OUTPUT = os.path.join(PROJECT_ROOT, "output", "decompiled")

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

_ENGINE_GLOBAL_WRITE_RE = re.compile(
    r"(?m)^[ \t]+(?:g_MyD3D|g_kControls)\s*="
)

_PROTECTED_SLOT_ALIAS_RE = re.compile(
    r"\b(?:engineRef|controlsRef|stateFuncRef|playerActionRef|"
    r"damageTemplateRef|actionTableRef|skillConfigRef|mathRef|stringRef|"
    r"tableRef|coroutineRef|ioRef|osRef|debugRef|packageRef|utf8Ref|bitRef|"
    r"pairsRef|ipairsRef|nextRef|typeRef|tonumberRef|tostringRef|assertRef|"
    r"errorRef|pcallRef|xpcallRef|selectRef|unpackRef|printRef)\d*\b"
)
_FUNCTION_LINE_RE = re.compile(r"^(?P<indent>[ \t]*)(?:function\b|.*=\s*function\b)")


def _localize_protected_slot_aliases(source):
    """Declare protected slot aliases inside the generated function scope.

    The aliases are names created by slotrenamer for bytecode registers.  They
    must not leak into Lua's global table merely because stripped bytecode does
    not retain the original local-variable declarations.
    """
    lines = source.splitlines()
    insertions = []

    for index, line in enumerate(lines):
        match = _FUNCTION_LINE_RE.match(line)
        if not match:
            continue

        indent = match.group("indent")
        end_index = index + 1
        while end_index < len(lines):
            if lines[end_index] == indent + "end":
                break
            end_index += 1
        if end_index >= len(lines):
            continue

        aliases = sorted(
            {
                alias
                for body_line in lines[index + 1:end_index]
                for alias in _PROTECTED_SLOT_ALIAS_RE.findall(body_line)
            }
        )
        if aliases:
            insertions.append((index + 1, indent + "\tlocal " + ", ".join(aliases)))

    for index, declaration in reversed(insertions):
        lines.insert(index, declaration)

    suffix = "\n" if source.endswith("\n") else ""
    return "\n".join(lines) + suffix


def _localize_captured_initializers(source):
    """Turn the first top-level initializer of each captured slot into local."""
    lines = source.splitlines()
    seen = set()
    initializer_re = re.compile(r"^(capturedLocal\d+)\s*=")

    for index, line in enumerate(lines):
        match = initializer_re.match(line)
        if not match or match.group(1) in seen:
            continue
        seen.add(match.group(1))
        lines[index] = "local " + line

    suffix = "\n" if source.endswith("\n") else ""
    return "\n".join(lines) + suffix


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
    import ljd.ast.upvaluerenamer
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
        try:
            ljd.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        # DCE understands raw T_SLOT registers. Running it after the friendly
        # renamer made generated locals look like user variables and kept
        # decompiler-only alias assignments alive.
        ljd.ast.upvaluerenamer.rename_upvalues(ast)
        ljd.ast.slotrenamer.rename_slots(ast)
        buf = io.StringIO()
        ljd.lua.writer.write(buf, ast)
        source = ljd.lua.postprocess.postprocess(buf.getvalue())
        source = _localize_protected_slot_aliases(source)
        source = _localize_captured_initializers(source)
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
        try:
            ljd.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        ljd.ast.upvaluerenamer.rename_upvalues(ast)
        ljd.ast.slotrenamer.rename_slots(ast)
        buf = io.StringIO()
        ljd.lua.writer.write(buf, ast)
        source = ljd.lua.postprocess.postprocess(buf.getvalue())
        source = _localize_protected_slot_aliases(source)
        source = _localize_captured_initializers(source)
        return (1, source)
    except (Exception, RecursionError):
        pass

    # Level 2: Mínimo
    try:
        ast = ljd.ast.builder.build(prototype)
        ljd.ast.mutator.pre_pass(ast)
        try:
            ljd.ast.dce.eliminate_dead_stores(ast)
        except Exception:
            pass
        ljd.ast.upvaluerenamer.rename_upvalues(ast)
        ljd.ast.slotrenamer.rename_slots(ast)
        buf = io.StringIO()
        ljd.lua.writer.write(buf, ast)
        source = ljd.lua.postprocess.postprocess(buf.getvalue())
        source = _localize_protected_slot_aliases(source)
        source = _localize_captured_initializers(source)
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
             "stg": 0, "copied": 0, "unresolved_warps": 0,
             "unsafe_engine_writes": 0}
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
                # Do not silently present an incomplete control-flow recovery as
                # a perfect decompilation.  The writer keeps unresolved KL
                # conditional warps as valid Lua comments, and we report their
                # count here so callers can review the affected files.
                unresolved = source.count("-- unresolved conditional warp")
                stats["unresolved_warps"] += unresolved
                stats["unsafe_engine_writes"] += len(
                    _ENGINE_GLOBAL_WRITE_RE.findall(source)
                )
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
            # Nao e KL: salvar separado para nao parecer Lua decompilado.
            raw_path = out_path + ".encrypted"
            if os.path.isfile(out_path):
                os.remove(out_path)
            with open(raw_path, "wb") as f:
                f.write(data)
            stats["failed"] += 1
            failed_files.append(rel)

        if (i % 20 == 0) or i == len(all_files):
            print(f"\r  [{i}/{len(all_files)}] {stats['ok']} OK, {stats['failed']} falhas...", end="", flush=True)

    elapsed = time.time() - t0
    print(f"\r  {'-'*50}")
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
    if stats["unresolved_warps"]:
        print(f"    Warps não resolvidos: {stats['unresolved_warps']}")
        print("      O Lua gerado é válido, mas esses pontos exigem revisão semântica.")

    if stats["unsafe_engine_writes"]:
        print(
            "    Escritas perigosas em globais da engine: "
            f"{stats['unsafe_engine_writes']}"
        )
        print("      Revise a renomeacao de slots antes de executar estes scripts.")

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
