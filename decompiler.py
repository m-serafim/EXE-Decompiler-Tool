#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXE Decompiler Tool
====================
Ferramenta completa de análise e descompilação de ficheiros EXE.

Suporta:
  - PyInstaller (extração + decompilação .pyc → .py)
  - .NET / C# (ilspycmd → código C# legível)
  - Go / C / C++ nativo (disassembly via capstone)
  - UPX packed (unpack automático)
  - Extração de strings, imports, exports, metadados e recursos

Uso:
  python decompiler.py <ficheiro.exe>
"""

import argparse
import datetime
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
from html import escape as html_escape
from pathlib import Path

# ---------------------------------------------------------------------------
# Lazy imports – show friendly message when a package is missing
# ---------------------------------------------------------------------------

_MISSING: list[str] = []


def _try_import(name: str):
    """Import *name* and return the module, or None on failure."""
    try:
        return __import__(name)
    except ImportError:
        _MISSING.append(name)
        return None


pefile = _try_import("pefile")
capstone = _try_import("capstone")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_DISASM_INSTRUCTIONS = 4096
MIN_STRING_LEN = 6
OUTPUT_DIR = "output"

# ANSI helpers (disabled when stdout is not a terminal)
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def info(msg: str) -> None:
    print(_c("0;36", f"[*] {msg}"))


def ok(msg: str) -> None:
    print(_c("0;32", f"[✓] {msg}"))


def warn(msg: str) -> None:
    print(_c("1;33", f"[!] {msg}"))


def error(msg: str) -> None:
    print(_c("0;31", f"[✗] {msg}"), file=sys.stderr)


# ===================================================================
# 1. VALIDAÇÃO INICIAL
# ===================================================================


def validate_file(path: str) -> Path:
    """Return a resolved *Path* if the file is a valid, reasonably‑sized EXE."""
    p = Path(path).resolve()
    if not p.is_file():
        error(f"Ficheiro não encontrado: {p}")
        sys.exit(1)

    size = p.stat().st_size
    if size > MAX_FILE_SIZE:
        error(
            f"Ficheiro demasiado grande ({size / 1024 / 1024:.2f} MB). "
            f"Limite: {MAX_FILE_SIZE / 1024 / 1024:.0f} MB."
        )
        sys.exit(1)

    with open(p, "rb") as fh:
        magic = fh.read(2)
    if magic != b"MZ":
        error("O ficheiro não é um EXE válido (magic bytes MZ não encontrados).")
        sys.exit(1)

    info(f"Ficheiro : {p.name}")
    info(f"Tamanho  : {size:,} bytes ({size / 1024:.1f} KB)")
    return p


# ===================================================================
# 2. DETECÇÃO AUTOMÁTICA DE TIPO
# ===================================================================


class ExeType:
    PYINSTALLER = "PyInstaller"
    DOTNET = ".NET / C#"
    GO = "Go"
    NUITKA = "Nuitka"
    CX_FREEZE = "cx_Freeze"
    UPX = "UPX packed"
    NATIVE = "C/C++ nativo"


def _read_overlay(data: bytes, pe) -> bytes:
    """Return the overlay (data after the last section) of a PE file."""
    overlay_offset = 0
    for section in pe.sections:
        end = section.PointerToRawData + section.SizeOfRawData
        if end > overlay_offset:
            overlay_offset = end
    return data[overlay_offset:]


def detect_type(exe_path: Path) -> tuple[str, object]:
    """Return (ExeType, pefile.PE) for the given EXE."""
    if pefile is None:
        warn("pefile não instalado – a assumir binário nativo.")
        return ExeType.NATIVE, None

    data = exe_path.read_bytes()
    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as exc:
        error(f"Erro ao analisar PE: {exc}")
        sys.exit(1)

    # --- UPX ---
    section_names = [s.Name.rstrip(b"\x00").decode(errors="replace") for s in pe.sections]
    if any("UPX" in n for n in section_names):
        ok(f"Tipo detectado: {ExeType.UPX}")
        return ExeType.UPX, pe

    # --- .NET ---
    clr_dir = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")
    if clr_dir is None:
        clr_dir = 14  # standard index
    try:
        clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[clr_dir]
        if clr.VirtualAddress != 0:
            ok(f"Tipo detectado: {ExeType.DOTNET}")
            return ExeType.DOTNET, pe
    except (IndexError, AttributeError):
        pass

    # --- PyInstaller ---
    overlay = _read_overlay(data, pe)
    if b"PyInstaller" in overlay or b"pyiboot" in data:
        ok(f"Tipo detectado: {ExeType.PYINSTALLER}")
        return ExeType.PYINSTALLER, pe

    # --- Go ---
    if b"go.buildid" in data or b"Go build ID:" in data:
        ok(f"Tipo detectado: {ExeType.GO}")
        return ExeType.GO, pe

    # --- Nuitka ---
    if b"nuitka" in data.lower() or any("nuitka" in n.lower() for n in section_names):
        ok(f"Tipo detectado: {ExeType.NUITKA}")
        return ExeType.NUITKA, pe

    # --- cx_Freeze ---
    if b"cx_Freeze" in data or b"cx_freeze" in data:
        ok(f"Tipo detectado: {ExeType.CX_FREEZE}")
        return ExeType.CX_FREEZE, pe

    # --- Native fallback ---
    ok(f"Tipo detectado: {ExeType.NATIVE}")
    return ExeType.NATIVE, pe


# ===================================================================
# 3. DESCOMPILAÇÃO POR TIPO
# ===================================================================

def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run *cmd* capturing output, suppressing errors on failure."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kwargs)
    except subprocess.TimeoutExpired:
        warn(f"Comando expirou após 120s: {' '.join(cmd[:2])}")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="Timeout")


def _ensure_dir(d: str) -> Path:
    p = Path(d)
    p.mkdir(parents=True, exist_ok=True)
    return p


def decompile_pyinstaller(exe_path: Path, source_dir: Path) -> list[str]:
    """Extract and decompile a PyInstaller EXE."""
    results: list[str] = []
    tmpdir = tempfile.mkdtemp(prefix="pyinst_")

    # Try pyinstxtractor (command‑line)
    pyinstxtractor = shutil.which("pyinstxtractor") or shutil.which("pyinstxtractor-ng")
    if pyinstxtractor:
        info("A extrair com pyinstxtractor…")
        r = _run([pyinstxtractor, str(exe_path), "-d", tmpdir])
        if r.returncode == 0:
            ok("Extração PyInstaller concluída.")
        else:
            warn(f"pyinstxtractor falhou: {r.stderr.strip()}")
    else:
        # Fallback: try as a Python module
        try:
            info("A tentar extrair via módulo pyinstxtractor…")
            r = _run([sys.executable, "-m", "pyinstxtractor", str(exe_path)], cwd=tmpdir)
            if r.returncode != 0:
                warn("Módulo pyinstxtractor falhou. Verifica se está instalado.")
        except Exception as exc:
            warn(f"Extração PyInstaller indisponível: {exc}")

    # Decompile any .pyc files found
    pyc_files = list(Path(tmpdir).rglob("*.pyc"))
    if not pyc_files:
        # Sometimes extraction drops to current directory
        pyc_files = list(Path(".").rglob("*.pyc"))

    decompiler_cmd = None
    for cmd_name in ("uncompyle6", "decompyle3"):
        if shutil.which(cmd_name):
            decompiler_cmd = cmd_name
            break

    for pyc in pyc_files:
        out_py = source_dir / pyc.with_suffix(".py").name
        if decompiler_cmd:
            r = _run([decompiler_cmd, str(pyc)])
            if r.returncode == 0 and r.stdout.strip():
                out_py.write_text(r.stdout, encoding="utf-8")
                results.append(str(out_py))
                continue
        # Fallback: copy the .pyc as-is
        dst = source_dir / pyc.name
        shutil.copy2(pyc, dst)
        results.append(str(dst))

    shutil.rmtree(tmpdir, ignore_errors=True)
    return results


def decompile_dotnet(exe_path: Path, source_dir: Path) -> list[str]:
    """Decompile a .NET EXE via ilspycmd."""
    results: list[str] = []
    ilspycmd = shutil.which("ilspycmd")
    if ilspycmd:
        info("A descompilar .NET com ilspycmd…")
        r = _run([ilspycmd, str(exe_path), "-o", str(source_dir)])
        if r.returncode == 0:
            ok("Descompilação .NET concluída.")
            results = [str(f) for f in source_dir.rglob("*.cs")]
        else:
            warn(f"ilspycmd falhou: {r.stderr.strip()}")
    else:
        warn("ilspycmd não encontrado. Instala com: dotnet tool install -g ilspycmd")
        warn("A aplicar fallback (disassembly + strings).")
    return results


def disassemble_native(exe_path: Path, source_dir: Path, pe) -> list[str]:
    """Disassemble a native (C/C++/Go) binary with capstone."""
    results: list[str] = []
    if capstone is None:
        warn("capstone não instalado – disassembly indisponível.")
        return results

    # Detect architecture
    if pe is None:
        warn("PE não disponível – a ignorar disassembly.")
        return results

    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        arch_label = "x86 (32-bit)"
    elif machine == 0x8664:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        arch_label = "x86-64 (64-bit)"
    else:
        warn(f"Arquitetura não suportada para disassembly (machine=0x{machine:04X}).")
        return results

    md.detail = False
    info(f"A fazer disassembly {arch_label}…")

    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = None
    for section in pe.sections:
        if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            code_section = section
            break
    if code_section is None and pe.sections:
        code_section = pe.sections[0]

    if code_section is None:
        warn("Nenhuma secção de código encontrada.")
        return results

    code = code_section.get_data()
    base = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    # Limit disassembly to first 4096 instructions for readability
    lines: list[str] = []
    lines.append(f"; Disassembly of {exe_path.name}")
    lines.append(f"; Architecture: {arch_label}")
    lines.append(f"; Entry point: 0x{pe.OPTIONAL_HEADER.ImageBase + entry:08X}")
    lines.append(f"; Code section: {code_section.Name.rstrip(b'\x00').decode(errors='replace')}")
    lines.append("")

    count = 0
    for insn in md.disasm(code, base):
        lines.append(f"  0x{insn.address:08X}:  {insn.mnemonic:<8s} {insn.op_str}")
        count += 1
        if count >= MAX_DISASM_INSTRUCTIONS:
            lines.append(f"\n; … (truncado após {MAX_DISASM_INSTRUCTIONS} instruções)")
            break

    out_file = source_dir / "disassembly.asm"
    out_file.write_text("\n".join(lines), encoding="utf-8")
    results.append(str(out_file))
    ok(f"Disassembly concluído: {count} instruções → {out_file.name}")
    return results


def try_upx_unpack(exe_path: Path) -> Path | None:
    """Attempt to unpack a UPX‑compressed EXE; return path to unpacked file."""
    upx = shutil.which("upx")
    if not upx:
        warn("UPX não encontrado. Instala com: apt install upx / brew install upx")
        return None

    tmp_fd, tmp_name = tempfile.mkstemp(suffix=".exe", prefix="upx_")
    os.close(tmp_fd)
    tmpfile = Path(tmp_name)
    shutil.copy2(exe_path, tmpfile)
    info("A tentar unpack UPX…")
    r = _run([upx, "-d", str(tmpfile)])
    if r.returncode == 0:
        ok("UPX unpack concluído.")
        return tmpfile
    warn(f"UPX unpack falhou: {r.stderr.strip()}")
    tmpfile.unlink(missing_ok=True)
    return None


# ===================================================================
# 4. EXTRAÇÃO COMPLEMENTAR
# ===================================================================


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    """Extract printable ASCII/UTF-8 strings of at least *min_len* characters."""
    pattern = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
    raw = pattern.findall(data)
    seen: set[str] = set()
    result: list[str] = []
    for s in raw:
        decoded = s.decode("ascii", errors="replace")
        if decoded not in seen:
            seen.add(decoded)
            result.append(decoded)
    return result


def extract_imports(pe) -> list[dict]:
    """Return a list of {dll, functions} dicts from the PE import table."""
    imports: list[dict] = []
    if pe is None:
        return imports
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="replace")
            funcs = []
            for imp in entry.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                funcs.append(name)
            imports.append({"dll": dll_name, "functions": funcs})
    except AttributeError:
        pass
    return imports


def extract_exports(pe) -> list[str]:
    """Return exported function names."""
    exports: list[str] = []
    if pe is None:
        return exports
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode(errors="replace") if exp.name else f"ordinal_{exp.ordinal}"
            exports.append(name)
    except AttributeError:
        pass
    return exports


def extract_metadata(exe_path: Path, pe) -> dict:
    """Build a structured metadata dict from the PE headers."""
    meta: dict = {
        "filename": exe_path.name,
        "size_bytes": exe_path.stat().st_size,
    }
    if pe is None:
        return meta

    machine = pe.FILE_HEADER.Machine
    arch_map = {0x14C: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)", 0xAA64: "ARM64"}
    meta["architecture"] = arch_map.get(machine, f"0x{machine:04X}")

    subsys_map = {
        1: "Native", 2: "Windows GUI", 3: "Windows Console",
        7: "POSIX Console", 9: "Windows CE", 14: "EFI Application",
    }
    meta["subsystem"] = subsys_map.get(
        pe.OPTIONAL_HEADER.Subsystem,
        f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})",
    )

    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        meta["compile_timestamp"] = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
    except (OSError, ValueError):
        meta["compile_timestamp"] = str(ts)

    meta["entry_point"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"
    meta["image_base"] = f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}"
    meta["sections"] = []
    for s in pe.sections:
        meta["sections"].append({
            "name": s.Name.rstrip(b"\x00").decode(errors="replace"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
        })

    # Version info
    try:
        if hasattr(pe, "VS_FIXEDFILEINFO"):
            fi = pe.VS_FIXEDFILEINFO[0]
            meta["file_version"] = (
                f"{(fi.FileVersionMS >> 16) & 0xFFFF}."
                f"{fi.FileVersionMS & 0xFFFF}."
                f"{(fi.FileVersionLS >> 16) & 0xFFFF}."
                f"{fi.FileVersionLS & 0xFFFF}"
            )
        if hasattr(pe, "FileInfo"):
            for fi_entry in pe.FileInfo:
                for entry in fi_entry:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode(errors="replace")
                                val = v.decode(errors="replace")
                                meta.setdefault("version_info", {})[key] = val
    except Exception:
        pass

    return meta


def extract_resources(pe, resource_dir: Path) -> list[str]:
    """Extract embedded resources (icons, manifests, etc.)."""
    extracted: list[str] = []
    if pe is None:
        return extracted
    try:
        entries = pe.DIRECTORY_ENTRY_RESOURCE.entries
    except AttributeError:
        return extracted

    resource_type_names = {
        1: "cursor", 2: "bitmap", 3: "icon", 4: "menu",
        5: "dialog", 6: "string_table", 9: "accelerator",
        10: "rcdata", 11: "message_table", 14: "group_icon",
        16: "version", 24: "manifest",
    }

    for res_type in entries:
        type_id = res_type.id if res_type.id is not None else 0
        type_name = resource_type_names.get(type_id, f"type_{type_id}")
        if not hasattr(res_type, "directory"):
            continue
        for res_id in res_type.directory.entries:
            if not hasattr(res_id, "directory"):
                continue
            for res_lang in res_id.directory.entries:
                try:
                    data_rva = res_lang.data.struct.OffsetToData
                    size = res_lang.data.struct.Size
                    data = pe.get_data(data_rva, size)
                    rid = res_id.id if res_id.id is not None else 0
                    fname = f"{type_name}_{rid}.bin"
                    # Give manifests a proper extension
                    if type_id == 24:
                        fname = f"manifest_{rid}.xml"
                    elif type_id == 3:
                        fname = f"icon_{rid}.ico"
                    out = resource_dir / fname
                    out.write_bytes(data)
                    extracted.append(str(out))
                except Exception:
                    continue
    return extracted


# ===================================================================
# 5. RELATÓRIO HTML
# ===================================================================


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    """Build an HTML <table> string."""
    h = "".join(f"<th>{html_escape(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        cells = "".join(f"<td>{html_escape(str(c))}</td>" for c in row)
        body += f"<tr>{cells}</tr>\n"
    return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def generate_report(
    exe_path: Path,
    exe_type: str,
    metadata: dict,
    imports: list[dict],
    exports: list[str],
    strings_count: int,
    source_files: list[str],
    resource_files: list[str],
    output_dir: Path,
) -> Path:
    """Generate an HTML report summarizing the analysis."""
    report_path = output_dir / "report.html"

    # Sections summary table
    section_rows = []
    for s in metadata.get("sections", []):
        section_rows.append([s["name"], str(s["virtual_size"]), str(s["raw_size"])])

    # Imports table
    import_rows = []
    for imp in imports:
        for func in imp["functions"]:
            import_rows.append([imp["dll"], func])

    html = textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html lang="pt">
    <head>
    <meta charset="UTF-8">
    <title>EXE Decompiler Report – {html_escape(exe_path.name)}</title>
    <style>
      :root {{ --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff; --card: #161b22; --border: #30363d; }}
      * {{ box-sizing: border-box; margin: 0; padding: 0; }}
      body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--fg); padding: 2rem; }}
      h1 {{ color: var(--accent); margin-bottom: .5rem; }}
      h2 {{ color: var(--accent); margin: 1.5rem 0 .5rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }}
      .badge {{ display: inline-block; background: var(--accent); color: #000; border-radius: 4px; padding: 2px 8px; font-weight: 600; margin-left: 8px; }}
      .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin: 1rem 0; }}
      .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
      .card .label {{ font-size: .85rem; color: #8b949e; }}
      .card .value {{ font-size: 1.1rem; margin-top: .25rem; word-break: break-all; }}
      table {{ width: 100%; border-collapse: collapse; margin: .5rem 0; }}
      th, td {{ text-align: left; padding: 6px 10px; border: 1px solid var(--border); }}
      th {{ background: var(--card); }}
      tr:nth-child(even) {{ background: var(--card); }}
      ul {{ margin-left: 1.5rem; }}
      footer {{ margin-top: 2rem; color: #484f58; font-size: .85rem; text-align: center; }}
    </style>
    </head>
    <body>
    <h1>🔍 EXE Decompiler Report</h1>
    <p><strong>{html_escape(exe_path.name)}</strong> <span class="badge">{html_escape(exe_type)}</span></p>

    <h2>📋 Metadados</h2>
    <div class="grid">
      <div class="card"><div class="label">Arquitectura</div><div class="value">{html_escape(metadata.get('architecture', 'N/A'))}</div></div>
      <div class="card"><div class="label">Subsistema</div><div class="value">{html_escape(metadata.get('subsystem', 'N/A'))}</div></div>
      <div class="card"><div class="label">Timestamp Compilação</div><div class="value">{html_escape(metadata.get('compile_timestamp', 'N/A'))}</div></div>
      <div class="card"><div class="label">Entry Point</div><div class="value">{html_escape(metadata.get('entry_point', 'N/A'))}</div></div>
      <div class="card"><div class="label">Image Base</div><div class="value">{html_escape(metadata.get('image_base', 'N/A'))}</div></div>
      <div class="card"><div class="label">Tamanho</div><div class="value">{metadata.get('size_bytes', 0):,} bytes</div></div>
    </div>

    <h2>📦 Secções PE</h2>
    {_html_table(['Nome', 'Tamanho Virtual', 'Tamanho Raw'], section_rows) if section_rows else '<p>Sem secções disponíveis.</p>'}

    <h2>📥 Imports ({len(import_rows)})</h2>
    {_html_table(['DLL', 'Função'], import_rows[:200]) if import_rows else '<p>Sem imports.</p>'}
    {'<p><em>… mais ' + str(len(import_rows) - 200) + ' entradas (ver imports.txt)</em></p>' if len(import_rows) > 200 else ''}

    <h2>📤 Exports ({len(exports)})</h2>
    {'<ul>' + ''.join(f'<li>{html_escape(e)}</li>' for e in exports[:100]) + '</ul>' if exports else '<p>Sem exports.</p>'}

    <h2>🔤 Strings</h2>
    <p>{strings_count:,} strings extraídas (ver <code>strings.txt</code>).</p>

    <h2>📝 Ficheiros Source Recuperados ({len(source_files)})</h2>
    {'<ul>' + ''.join(f'<li>{html_escape(os.path.basename(f))}</li>' for f in source_files) + '</ul>' if source_files else '<p>Nenhum ficheiro source recuperado.</p>'}

    <h2>🎨 Recursos Extraídos ({len(resource_files)})</h2>
    {'<ul>' + ''.join(f'<li>{html_escape(os.path.basename(f))}</li>' for f in resource_files) + '</ul>' if resource_files else '<p>Nenhum recurso extraído.</p>'}

    <footer>Gerado por EXE Decompiler Tool &mdash; {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
    </body>
    </html>
    """)

    report_path.write_text(html, encoding="utf-8")
    return report_path


# ===================================================================
# 6. MAIN – INTERFACE CLI
# ===================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EXE Decompiler Tool – Ferramenta completa de análise e descompilação de EXEs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Exemplos:
              python decompiler.py programa.exe
              python decompiler.py malware_sample.exe
        """),
    )
    parser.add_argument("exe", help="Caminho para o ficheiro .exe a analisar")
    args = parser.parse_args()

    # Check critical dependencies
    if _MISSING:
        error(f"Dependências em falta: {', '.join(_MISSING)}")
        error("Executa: pip install -r requirements.txt")
        sys.exit(1)

    print()
    print(_c("1;35", "╔══════════════════════════════════════════╗"))
    print(_c("1;35", "║        EXE Decompiler Tool  v1.0         ║"))
    print(_c("1;35", "╚══════════════════════════════════════════╝"))
    print()

    # 1. Validate
    exe_path = validate_file(args.exe)

    # 2. Detect type
    exe_type, pe = detect_type(exe_path)

    # Prepare output directories
    out_root = _ensure_dir(OUTPUT_DIR)
    source_dir = _ensure_dir(out_root / "source")
    resource_dir = _ensure_dir(out_root / "resources")

    # 3. UPX unpack first if needed
    unpacked_path: Path | None = None
    if exe_type == ExeType.UPX:
        unpacked_path = try_upx_unpack(exe_path)
        if unpacked_path:
            # Re‑detect the underlying type
            exe_type, pe = detect_type(unpacked_path)
            exe_path_for_analysis = unpacked_path
        else:
            exe_path_for_analysis = exe_path
    else:
        exe_path_for_analysis = exe_path

    # 4. Decompile / disassemble
    source_files: list[str] = []
    if exe_type == ExeType.PYINSTALLER:
        source_files = decompile_pyinstaller(exe_path_for_analysis, source_dir)
    elif exe_type == ExeType.DOTNET:
        source_files = decompile_dotnet(exe_path_for_analysis, source_dir)
    elif exe_type in (ExeType.GO, ExeType.NATIVE, ExeType.NUITKA, ExeType.CX_FREEZE):
        source_files = disassemble_native(exe_path_for_analysis, source_dir, pe)

    # 5. Complementary extraction
    data = exe_path_for_analysis.read_bytes()

    info("A extrair strings…")
    strings = extract_strings(data)
    strings_file = out_root / "strings.txt"
    strings_file.write_text("\n".join(strings), encoding="utf-8")
    ok(f"{len(strings):,} strings extraídas → strings.txt")

    info("A extrair imports / exports…")
    imports = extract_imports(pe)
    exports = extract_exports(pe)
    imports_text_lines: list[str] = ["=== IMPORTS ===\n"]
    for imp in imports:
        imports_text_lines.append(f"[{imp['dll']}]")
        for f in imp["functions"]:
            imports_text_lines.append(f"  {f}")
        imports_text_lines.append("")
    imports_text_lines.append("\n=== EXPORTS ===\n")
    for e in exports:
        imports_text_lines.append(f"  {e}")
    (out_root / "imports.txt").write_text("\n".join(imports_text_lines), encoding="utf-8")

    total_funcs = sum(len(i["functions"]) for i in imports)
    ok(f"Imports: {len(imports)} DLLs, {total_funcs} funções | Exports: {len(exports)}")

    info("A extrair metadados PE…")
    metadata = extract_metadata(exe_path, pe)
    (out_root / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    ok("Metadados guardados → metadata.json")

    info("A extrair recursos…")
    resource_files = extract_resources(pe, resource_dir)
    ok(f"{len(resource_files)} recursos extraídos → resources/")

    # 6. HTML report
    info("A gerar relatório HTML…")
    report = generate_report(
        exe_path, exe_type, metadata, imports, exports,
        len(strings), source_files, resource_files, out_root,
    )
    ok(f"Relatório gerado → {report}")

    # Cleanup
    if unpacked_path:
        unpacked_path.unlink(missing_ok=True)

    print()
    ok("Análise concluída! Resultados em: output/")
    print()


if __name__ == "__main__":
    main()
