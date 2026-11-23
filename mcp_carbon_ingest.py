#!/usr/bin/env python3
"""
mcp_carbon_ingest.py — Stage 0 Argon-Carbon Local Research Orchestrator
Author: Eloquent (@mjeanhudson-dev)
Zero-dependency CLI (Python 3.10+ stdlib only) for indexing MCP codebases,
Chrome/.url research links, Jupyter notebooks, .zip archives, and .vhdx
virtual disk archives into SQLite WAL + BM25 FTS5.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import configparser
import hashlib
import json
import mmap
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# --- Stage 0 Deterministic Constants ---
MAX_FILE_BYTES = 64 * 1024 * 1024  # 64 MB ceiling for direct text read
SLICE_MAX_LINES = 160              # Carbon Stage 0 slice invariant

EXCLUDED_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    "target", ".next", ".turbo", ".cache", ".idea", ".vscode",
})

TEXT_CODE_EXTS = frozenset({
    ".py", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".md", ".txt", ".rst", ".json", ".toml", ".yaml", ".yml",
    ".ts", ".tsx", ".js", ".jsx", ".rs", ".go", ".sql", ".proto",
})

LINK_EXTS = frozenset({".url", ".webloc", ".desktop", ".html", ".htm"})

# High-confidence credential patterns scrubbed prior to FTS indexing.
# Order matters: ANTHROPIC_KEY (sk-ant-*) must precede generic OPENAI_KEY (sk-*).
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GOOGLE_OAUTH_TOKEN", re.compile(r"AQ\.Ab8[0-9A-Za-z._\-]{15,}|ya29\.[0-9A-Za-z_\-]{20,}")),
    ("GOOGLE_OAUTH_SECRET", re.compile(r"GOCSPX-[A-Za-z0-9_\-]{18,}")),
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("GITHUB_TOKEN", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}")),
    ("AWS_ACCESS_KEY", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("ENV_SECRET", re.compile(
        r"(?im)^([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*)(['\"]?[^\s#'\"]{8,}['\"]?)"
    )),
)

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]`\\({}]+")
NOTEBOOK_URL_HINTS = (
    "colab.research.google.com",
    "notebooklm.google.com",
    "gemini.google.com/notebook",
    ".ipynb",
    "kaggle.com/code",
    "huggingface.co",
    "modelcontextprotocol",
)


@dataclass
class SecretHit:
    secret_type: str
    line_number: int


@dataclass
class LinkRecord:
    url: str
    category: str
    context: str


@dataclass
class FilePayload:
    path: str
    folder_root: str
    ext: str
    size_bytes: int
    sha256: str
    ast_summary: str = ""
    slices: list[tuple[int, int, int, str]] = field(default_factory=list)
    links: list[LinkRecord] = field(default_factory=list)
    secrets: list[SecretHit] = field(default_factory=list)
    error: str = ""


def compute_mmap_sha256(path: Path) -> tuple[int, str]:
    """Zero-copy memory-mapped SHA-256 digest (safe on 0-byte files)."""
    size = path.stat().st_size
    if size == 0:
        return 0, hashlib.sha256(b"").hexdigest()
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for offset in range(0, size, 4 * 1024 * 1024):
                hasher.update(mm[offset : offset + 4 * 1024 * 1024])
    return size, hasher.hexdigest()


def scrub_secrets(text: str) -> tuple[str, list[SecretHit]]:
    """Scans and redacts API keys/secrets line-by-line before indexing."""
    hits: list[SecretHit] = []
    out_lines: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        scrubbed = line
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(scrubbed):
                hits.append(SecretHit(secret_type=label, line_number=idx))
                if label == "ENV_SECRET":
                    scrubbed = pattern.sub(rf"\1[REDACTED:{label}]", scrubbed)
                else:
                    scrubbed = pattern.sub(f"[REDACTED:{label}]", scrubbed)
        out_lines.append(scrubbed)
    return "\n".join(out_lines), hits


def classify_url(url: str) -> str:
    lowered = url.lower()
    if any(hint in lowered for hint in NOTEBOOK_URL_HINTS):
        return "notebook_or_mcp_hub"
    if "github.com" in lowered or "gitlab.com" in lowered:
        return "git_repository"
    return "web_reference"


def extract_links_from_text(text: str, source_label: str) -> list[LinkRecord]:
    seen: set[str] = set()
    records: list[LinkRecord] = []
    for match in URL_REGEX.finditer(text):
        clean_url = match.group(0).rstrip(".,;:)'\\\"")
        if clean_url and clean_url not in seen:
            seen.add(clean_url)
            records.append(LinkRecord(
                url=clean_url,
                category=classify_url(clean_url),
                context=source_label,
            ))
    return records


def parse_windows_url_shortcut(path: Path) -> list[LinkRecord]:
    """Extracts target URLs from Windows Chrome .url / .desktop files."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    parser = configparser.ConfigParser(interpolation=None)
    records: list[LinkRecord] = []
    try:
        parser.read_string(raw)
        for section in parser.sections():
            if parser.has_option(section, "URL"):
                target = parser.get(section, "URL").strip()
                if target:
                    records.append(LinkRecord(
                        url=target,
                        category=classify_url(target),
                        context=f"Shortcut:{path.name}",
                    ))
    except configparser.Error:
        records.extend(extract_links_from_text(raw, f"ShortcutFallback:{path.name}"))
    return records


def extract_python_ast_header(source: str) -> str:
    """Deterministic Stage 0 AST skeleton extractor for Python modules."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return f"[AST_SYNTAX_WARN line={exc.lineno}]"

    summary_lines: list[str] = []
    doc = ast.get_docstring(tree)
    if doc:
        first_line = doc.strip().splitlines()[0][:140]
        summary_lines.append(f'"""{first_line}"""')

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            m_str = ", ".join(methods[:8]) + ("..." if len(methods) > 8 else "")
            summary_lines.append(f"class {node.name} [{m_str}] (L{node.lineno})")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            args = [a.arg for a in node.args.args[:6]]
            summary_lines.append(f"{prefix} {node.name}({', '.join(args)}) (L{node.lineno})")

    return "\n".join(summary_lines[:60])


def parse_ipynb_native(raw_text: str) -> str:
    """Zero-subprocess Jupyter .ipynb cleaner; strips bloated base64 outputs."""
    data = json.loads(raw_text)
    cells = data.get("cells", [])
    rendered: list[str] = []
    for idx, cell in enumerate(cells, start=1):
        ctype = cell.get("cell_type", "unknown")
        src = cell.get("source", [])
        body = "".join(src) if isinstance(src, list) else str(src)
        if not body.strip():
            continue
        rendered.append(f"# --- [CELL {idx} | {ctype.upper()}] ---\n{body.strip()}")
    return "\n\n".join(rendered)


def slice_text_160(text: str) -> list[tuple[int, int, int, str]]:
    """Chunks cleaned text into <= 160-line Stage 0 slices."""
    lines = text.splitlines()
    if not lines:
        return []
    slices: list[tuple[int, int, int, str]] = []
    chunk_idx = 0
    for start in range(0, len(lines), SLICE_MAX_LINES):
        end = min(start + SLICE_MAX_LINES, len(lines))
        chunk_body = "\n".join(lines[start:end])
        slices.append((chunk_idx, start + 1, end, chunk_body))
        chunk_idx += 1
    return slices


def process_single_file(task: tuple[str, str]) -> FilePayload:
    """Worker entrypoint executed across ProcessPoolExecutor."""
    file_str, root_label = task
    path = Path(file_str)
    ext = path.suffix.lower()

    try:
        size_bytes, sha256 = compute_mmap_sha256(path)
        payload = FilePayload(
            path=str(path),
            folder_root=root_label,
            ext=ext,
            size_bytes=size_bytes,
            sha256=sha256,
        )

        if size_bytes == 0 or size_bytes > MAX_FILE_BYTES:
            return payload

        if ext in (".url", ".desktop"):
            payload.links = parse_windows_url_shortcut(path)
            return payload

        if ext in LINK_EXTS:
            raw = path.read_text(encoding="utf-8", errors="replace")
            scrubbed, hits = scrub_secrets(raw)
            payload.secrets = hits
            payload.links = extract_links_from_text(scrubbed, path.name)
            return payload

        if ext == ".ipynb":
            raw = path.read_text(encoding="utf-8", errors="replace")
            cleaned_nb = parse_ipynb_native(raw)
            scrubbed, hits = scrub_secrets(cleaned_nb)
            payload.secrets = hits
            payload.links = extract_links_from_text(scrubbed, f"Notebook:{path.name}")
            payload.slices = slice_text_160(scrubbed)
            return payload

        if ext in TEXT_CODE_EXTS:
            raw = path.read_text(encoding="utf-8", errors="replace")
            scrubbed, hits = scrub_secrets(raw)
            payload.secrets = hits
            if ext == ".py":
                raw_ast = extract_python_ast_header(raw)
                payload.ast_summary, _ = scrub_secrets(raw_ast)
            if ext in (".md", ".txt", ".rst", ".json", ".toml", ".yaml", ".yml", ".sh"):
                payload.links = extract_links_from_text(scrubbed, path.name)
            payload.slices = slice_text_160(scrubbed)
            return payload

        return payload
    except Exception as exc:
        return FilePayload(
            path=str(path),
            folder_root=root_label,
            ext=ext,
            size_bytes=0,
            sha256="",
            error=f"{type(exc).__name__}: {exc}",
        )


def resolve_7z_binary() -> str | None:
    """Resolves 7-Zip across PATH and standard Windows install paths."""
    for candidate in ("7z", "7zz"):
        found = shutil.which(candidate)
        if found:
            return found
    win_paths = (
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    )
    for wp in win_paths:
        if wp.exists():
            return str(wp)
    return None


def parse_7z_slt_entries(stdout: str, vhdx_path: Path, size_mb: float) -> list[tuple[str, str, int, str]]:
    """Parses `7z l -slt` entry blocks strictly after the `----------` boundary."""
    rows: list[tuple[str, str, int, str]] = []
    in_entries = False
    cur_path = ""
    cur_size = 0
    cur_fs = ""
    cur_offset = ""

    def flush() -> None:
        nonlocal cur_path, cur_size, cur_fs, cur_offset
        if cur_path and cur_path != str(vhdx_path):
            extras = [f"inspect ({size_mb:.1f} MB image)"]
            if cur_fs:
                extras.append(f"fs={cur_fs}")
            if cur_offset:
                extras.append(f"offset={cur_offset}")
            rows.append((str(vhdx_path), cur_path, cur_size, " | ".join(extras)))
        cur_path = ""
        cur_size = 0
        cur_fs = ""
        cur_offset = ""

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not in_entries:
            if line.startswith("----------"):
                in_entries = True
            continue
        if not line:
            flush()
            continue
        if line.startswith("Path = "):
            if cur_path:
                flush()
            cur_path = line[7:].strip()
        elif line.startswith("Size = "):
            val = line[7:].strip()
            cur_size = int(val) if val.isdigit() else 0
        elif line.startswith("File System = "):
            cur_fs = line[14:].strip()
        elif line.startswith("Offset = "):
            cur_offset = line[9:].strip()
    flush()
    return rows


def handle_vhdx_archives(
    vhdx_files: list[Path],
    mode: str,
    extract_root: Path,
    conn: sqlite3.Connection,
) -> tuple[int, list[Path]]:
    """Safely inspects, mounts, or selectively extracts .vhdx virtual disks."""
    if not vhdx_files:
        return 0, []

    seven_zip = resolve_7z_binary()
    extracted_roots: list[Path] = []
    cataloged_entries = 0

    for vhdx in vhdx_files:
        size_bytes = vhdx.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        conn.execute("DELETE FROM vhdx_manifest WHERE vhdx_path = ?", (str(vhdx),))

        if mode == "mount-command":
            ps_cmd = f'Mount-DiskImage -ImagePath "{vhdx.resolve()}" -ReadOnly'
            wsl_cmd = f'wsl --mount --vhd "{vhdx.resolve()}" --bare'
            conn.execute(
                "INSERT INTO vhdx_manifest (vhdx_path, entry_path, entry_size, mode_note) VALUES (?, ?, ?, ?)",
                (str(vhdx), "[MOUNT_READY]", int(size_bytes), f"PS: {ps_cmd} | WSL: {wsl_cmd}"),
            )
            cataloged_entries += 1
            continue

        if not seven_zip:
            conn.execute(
                "INSERT INTO vhdx_manifest (vhdx_path, entry_path, entry_size, mode_note) VALUES (?, ?, ?, ?)",
                (
                    str(vhdx),
                    "[7Z_NOT_FOUND]",
                    int(size_bytes),
                    f"Install 7-Zip or run PowerShell: Mount-DiskImage -ImagePath '{vhdx.resolve()}' -ReadOnly",
                ),
            )
            continue

        if mode == "inspect":
            proc = subprocess.run(
                [seven_zip, "l", "-slt", str(vhdx)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            )
            rows = parse_7z_slt_entries(proc.stdout, vhdx, size_mb)
            if rows:
                conn.executemany(
                    "INSERT INTO vhdx_manifest (vhdx_path, entry_path, entry_size, mode_note) VALUES (?, ?, ?, ?)",
                    rows[:5000],
                )
                cataloged_entries += len(rows)
            else:
                conn.execute(
                    "INSERT INTO vhdx_manifest (vhdx_path, entry_path, entry_size, mode_note) VALUES (?, ?, ?, ?)",
                    (str(vhdx), "[NO_ENTRIES_LISTED]", int(size_bytes), f"inspect rc={proc.returncode} ({size_mb:.1f} MB image)"),
                )

        elif mode == "selective-extract":
            target_dir = extract_root / vhdx.stem
            target_dir.mkdir(parents=True, exist_ok=True)
            include_flags = [f"-ir!*{ext}" for ext in (".py", ".sh", ".md", ".ipynb", ".json", ".toml", ".yaml", ".url")]
            exclude_flags = ["-xr!node_modules", "-xr!.git", "-xr!.venv", "-xr!__pycache__"]
            cmd = [seven_zip, "x", str(vhdx), f"-o{target_dir}", "-y", *include_flags, *exclude_flags]
            subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
            extracted_roots.append(target_dir)
            cataloged_entries += 1

    conn.commit()
    return cataloged_entries, extracted_roots


def handle_zip_archives(
    zip_files: list[tuple[Path, str]],
    conn: sqlite3.Connection,
) -> int:
    """Safely catalogs .zip internal file manifests via stdlib zipfile without extracting."""
    if not zip_files:
        return 0

    cataloged_entries = 0
    for zp, root_label in zip_files:
        conn.execute("DELETE FROM zip_manifest WHERE zip_path = ?", (str(zp),))
        try:
            with zipfile.ZipFile(zp, "r") as zf:
                rows = [
                    (str(zp), root_label, info.filename, info.file_size, info.compress_size)
                    for info in zf.infolist()
                    if not info.is_dir()
                ]
            if rows:
                conn.executemany(
                    """INSERT INTO zip_manifest
                       (zip_path, folder_root, entry_path, entry_size, compressed_size)
                       VALUES (?, ?, ?, ?, ?)""",
                    rows[:10000],
                )
                cataloged_entries += len(rows)
        except (zipfile.BadZipFile, OSError) as exc:
            conn.execute(
                """INSERT INTO zip_manifest
                   (zip_path, folder_root, entry_path, entry_size, compressed_size)
                   VALUES (?, ?, ?, ?, ?)""",
                (str(zp), root_label, f"[ZIP_ERROR: {type(exc).__name__}]", 0, 0),
            )
    conn.commit()
    return cataloged_entries


def init_vault_db(db_path: Path) -> tuple[sqlite3.Connection, bool]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA mmap_size=268435456;")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            sha256 TEXT NOT NULL,
            path TEXT UNIQUE NOT NULL,
            folder_root TEXT NOT NULL,
            ext TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            ast_summary TEXT,
            is_duplicate INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);

        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY,
            source_path TEXT NOT NULL,
            url TEXT NOT NULL,
            category TEXT NOT NULL,
            context TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_links_cat ON links(category);

        CREATE TABLE IF NOT EXISTS secret_audit (
            id INTEGER PRIMARY KEY,
            source_path TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            line_number INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vhdx_manifest (
            id INTEGER PRIMARY KEY,
            vhdx_path TEXT NOT NULL,
            entry_path TEXT NOT NULL,
            entry_size INTEGER NOT NULL,
            mode_note TEXT
        );

        CREATE TABLE IF NOT EXISTS zip_manifest (
            id INTEGER PRIMARY KEY,
            zip_path TEXT NOT NULL,
            folder_root TEXT NOT NULL,
            entry_path TEXT NOT NULL,
            entry_size INTEGER NOT NULL,
            compressed_size INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_zip_manifest_path ON zip_manifest(zip_path);
    """)

    fts_enabled = True
    try:
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS slices_fts USING fts5(
                path,
                folder_root,
                chunk_index UNINDEXED,
                line_range UNINDEXED,
                ast_summary,
                content,
                tokenize='porter unicode61'
            );
        """)
    except sqlite3.OperationalError:
        fts_enabled = False
        conn.execute("""
            CREATE TABLE IF NOT EXISTS slices_fallback (
                path TEXT,
                folder_root TEXT,
                chunk_index INTEGER,
                line_range TEXT,
                ast_summary TEXT,
                content TEXT
            );
        """)
    conn.commit()
    return conn, fts_enabled


def walk_candidate_files(
    roots: Iterable[Path],
) -> tuple[list[tuple[str, str]], list[Path], list[tuple[Path, str]]]:
    tasks: list[tuple[str, str]] = []
    vhdx_list: list[Path] = []
    zip_list: list[tuple[Path, str]] = []
    for root in roots:
        if not root.exists():
            print(f"[WARN] Root not found, skipping: {root}", file=sys.stderr)
            continue
        root_label = root.name
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in sorted(dirnames) if d not in EXCLUDED_DIRS]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                ext = fpath.suffix.lower()
                if ext == ".vhdx":
                    vhdx_list.append(fpath)
                elif ext == ".zip":
                    zip_list.append((fpath, root_label))
                elif ext in TEXT_CODE_EXTS or ext in LINK_EXTS or ext == ".ipynb":
                    tasks.append((str(fpath), root_label))
    return tasks, vhdx_list, zip_list


def cmd_ingest(args: argparse.Namespace) -> None:
    t0 = time.perf_counter()
    db_path = Path(args.db).resolve()
    roots = [Path(r).resolve() for r in args.roots]
    extract_dir = Path(args.extract_dir).resolve()

    conn, fts_enabled = init_vault_db(db_path)
    tasks, vhdx_files, zip_files = walk_candidate_files(roots)

    vhdx_count, extra_roots = handle_vhdx_archives(vhdx_files, args.vhdx_mode, extract_dir, conn)
    zip_count = handle_zip_archives(zip_files, conn)
    if extra_roots:
        extra_tasks, _, extra_zips = walk_candidate_files(extra_roots)
        tasks.extend(extra_tasks)
        zip_count += handle_zip_archives(extra_zips, conn)

    seen_hashes: set[str] = {
        row[0] for row in conn.execute("SELECT DISTINCT sha256 FROM files WHERE sha256 != ''")
    }

    workers = args.workers or max(2, (os.cpu_count() or 4) - 1)
    indexed_files = 0
    dedup_skipped = 0
    total_slices = 0
    total_links = 0
    total_secrets = 0

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
        with conn:
            for payload in pool.map(process_single_file, tasks, chunksize=24):
                if payload.error:
                    print(f"[WARN] Skipped {payload.path}: {payload.error}", file=sys.stderr)
                    continue
                is_dup = payload.sha256 in seen_hashes and payload.sha256 != ""
                conn.execute(
                    """INSERT OR REPLACE INTO files
                       (sha256, path, folder_root, ext, size_bytes, ast_summary, is_duplicate)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        payload.sha256, payload.path, payload.folder_root, payload.ext,
                        payload.size_bytes, payload.ast_summary, int(is_dup),
                    ),
                )
                indexed_files += 1

                conn.execute("DELETE FROM secret_audit WHERE source_path = ?", (payload.path,))
                if payload.secrets:
                    conn.executemany(
                        "INSERT INTO secret_audit (source_path, secret_type, line_number) VALUES (?, ?, ?)",
                        [(payload.path, s.secret_type, s.line_number) for s in payload.secrets],
                    )
                    total_secrets += len(payload.secrets)

                conn.execute("DELETE FROM links WHERE source_path = ?", (payload.path,))
                if payload.links:
                    conn.executemany(
                        "INSERT INTO links (source_path, url, category, context) VALUES (?, ?, ?, ?)",
                        [(payload.path, l.url, l.category, l.context) for l in payload.links],
                    )
                    total_links += len(payload.links)

                if is_dup:
                    dedup_skipped += 1
                    continue

                if payload.sha256:
                    seen_hashes.add(payload.sha256)

                if payload.slices:
                    table = "slices_fts" if fts_enabled else "slices_fallback"
                    conn.executemany(
                        f"INSERT INTO {table} (path, folder_root, chunk_index, line_range, ast_summary, content) VALUES (?, ?, ?, ?, ?, ?)",
                        [
                            (
                                payload.path, payload.folder_root, c_idx, f"L{l_start}-L{l_end}",
                                payload.ast_summary if c_idx == 0 else "", body,
                            )
                            for c_idx, l_start, l_end, body in payload.slices
                        ],
                    )
                    total_slices += len(payload.slices)

    elapsed = time.perf_counter() - t0
    vault_hash = hashlib.sha256(f"{indexed_files}:{total_slices}:{total_links}:{total_secrets}".encode()).hexdigest()[:16]

    # Stage 0 Compact Telemetry Receipt (< 300 tokens)
    print(f"[CARBON_STAGE_0_RECEIPT] vault={db_path.name} parity={vault_hash} elapsed={elapsed:.2f}s workers={workers}")
    print(
        f"[METRICS] files={indexed_files} dedup_shunted={dedup_skipped} slices_160L={total_slices} "
        f"links={total_links} vhdx_entries={vhdx_count} zip_entries={zip_count}"
    )
    print(
        f"[SECURITY_SIEVE] secrets_redacted={total_secrets} fts5_active={fts_enabled} "
        f"status={'SCRUBBED_SAFE_INDEX' if total_secrets else 'CLEAN'}"
    )


def cmd_query(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(str(Path(args.db).resolve()))
    try:
        rows = conn.execute(
            """SELECT path, line_range, ast_summary, snippet(slices_fts, 5, '>>>', '<<<', ' ... ', 28)
               FROM slices_fts WHERE slices_fts MATCH ? ORDER BY rank LIMIT ?""",
            (args.search_query, args.top),
        ).fetchall()
    except sqlite3.OperationalError:
        rows = conn.execute(
            """SELECT path, line_range, ast_summary, substr(content, 1, 240)
               FROM slices_fallback WHERE content LIKE ? LIMIT ?""",
            (f"%{args.search_query}%", args.top),
        ).fetchall()

    for idx, (path, lrange, ast_sum, snip) in enumerate(rows, start=1):
        print(f"\n[{idx}] {path} ({lrange})")
        if ast_sum:
            first_sig = " | ".join(ast_sum.splitlines()[:3])
            print(f"    AST: {first_sig}")
        print(f"    HIT: {snip.strip()}")


def cmd_audit(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(str(Path(args.db).resolve()))
    print("=== SECRET REDACTION AUDIT (DO NOT SHARE RAW FILES LISTED BELOW) ===")
    for path, stype, count in conn.execute(
        "SELECT source_path, secret_type, COUNT(*) FROM secret_audit GROUP BY source_path, secret_type ORDER BY COUNT(*) DESC LIMIT 30"
    ):
        print(f"  [!] {stype} ({count}x) -> {path}")

    print("\n=== HARVESTED MCP / NOTEBOOK LINKS (TOP 25) ===")
    for cat, url, src in conn.execute(
        "SELECT category, url, source_path FROM links ORDER BY category LIMIT 25"
    ):
        print(f"  [{cat}] {url}  (from {Path(src).name})")

    vhdx_rows = conn.execute(
        "SELECT vhdx_path, entry_path, entry_size, mode_note FROM vhdx_manifest ORDER BY vhdx_path, id LIMIT 25"
    ).fetchall()
    if vhdx_rows:
        print("\n=== VHDX ARCHIVE MANIFEST (TOP 25) ===")
        for vpath, epath, esize, note in vhdx_rows:
            print(f"  [{Path(vpath).name}] {epath} ({esize:,} bytes) — {note}")

    zip_summary = conn.execute(
        """SELECT zip_path, COUNT(*), COALESCE(SUM(entry_size), 0)
           FROM zip_manifest GROUP BY zip_path ORDER BY zip_path"""
    ).fetchall()
    if zip_summary:
        print("\n=== ZIP ARCHIVE INVENTORY ===")
        for zpath, cnt, total_sz in zip_summary:
            print(f"  [{Path(zpath).name}] {cnt} files ({total_sz / (1024 * 1024):.2f} MB uncompressed)")


def _normalize_export_path(raw_path: str) -> str:
    home_str = str(Path.home())
    text = str(raw_path or "")
    if text.lower().startswith(home_str.lower()):
        return "~" + text[len(home_str):].replace("\\", "/")
    return text.replace("\\", "/")


def mint_gcp_bearer_token(impersonate_sa: str = "") -> tuple[str, str]:
    """Return (bearer_token, source). Token lives in RAM only; never printed or written to disk.

    Order: GOOGLE_OAUTH_ACCESS_TOKEN env -> gcloud impersonating a service account (keyless) -> gcloud default login.
    """
    env_tok = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "").strip()
    if env_tok:
        return env_tok, "env_access_token"
    sa = (impersonate_sa or os.environ.get("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "")).strip()
    gcloud_exe = shutil.which("gcloud.cmd") or shutil.which("gcloud")
    if not gcloud_exe:
        raise RuntimeError("gcloud CLI not found; set GOOGLE_OAUTH_ACCESS_TOKEN or install the Google Cloud SDK.")
    cmd = [gcloud_exe, "auth", "print-access-token"]
    if sa:
        cmd.append(f"--impersonate-service-account={sa}")
    env = os.environ.copy()
    env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=env, timeout=40, check=False)
    tok = proc.stdout.strip()
    if proc.returncode != 0 or len(tok) < 20:
        raise RuntimeError(f"token mint failed (exit={proc.returncode}): {(proc.stderr or '').strip()[-300:]}")
    return tok, ("impersonated_service_account" if sa else "gcloud_default_login")


class GcpRest:
    """Minimal stdlib REST client for Cloud Storage and BigQuery using a Bearer token."""

    def __init__(self, token: str, project: str) -> None:
        self._headers = {"Authorization": f"Bearer {token}", "X-Goog-User-Project": project}
        self.project = project

    def call(self, method: str, url: str, body: bytes | None = None, content_type: str = "application/json",
             ok_404: bool = False) -> dict | None:
        headers = dict(self._headers)
        if body is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and ok_404:
                return None
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"{method} {url.split('?')[0]} -> HTTP {exc.code}: {detail}") from None

    def ensure_bucket(self, bucket: str, location: str) -> None:
        q = urllib.parse.quote
        if self.call("GET", f"https://storage.googleapis.com/storage/v1/b/{q(bucket, safe='')}", ok_404=True) is not None:
            return
        spec = {"name": bucket, "location": location, "storageClass": "STANDARD",
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}
        self.call("POST", f"https://storage.googleapis.com/storage/v1/b?project={q(self.project, safe='')}",
                  json.dumps(spec).encode("utf-8"))

    def upload_object(self, bucket: str, name: str, data: bytes) -> None:
        q = urllib.parse.quote
        self.call("POST",
                  f"https://storage.googleapis.com/upload/storage/v1/b/{q(bucket, safe='')}/o?uploadType=media&name={q(name, safe='')}",
                  data, content_type="application/json")

    def ensure_dataset(self, dataset: str, location: str) -> None:
        q = urllib.parse.quote
        base = f"https://bigquery.googleapis.com/bigquery/v2/projects/{q(self.project, safe='')}/datasets"
        if self.call("GET", f"{base}/{q(dataset, safe='')}", ok_404=True) is not None:
            return
        spec = {"datasetReference": {"projectId": self.project, "datasetId": dataset}, "location": location}
        self.call("POST", base, json.dumps(spec).encode("utf-8"))

    def load_table(self, bucket: str, prefix: str, dataset: str, table: str, location: str) -> None:
        q = urllib.parse.quote
        jobs = f"https://bigquery.googleapis.com/bigquery/v2/projects/{q(self.project, safe='')}/jobs"
        src = f"gs://{bucket}/{prefix}/{table}.jsonl" if prefix else f"gs://{bucket}/{table}.jsonl"
        spec = {
            "jobReference": {"projectId": self.project, "location": location},
            "configuration": {"load": {
                "sourceUris": [src],
                "destinationTable": {"projectId": self.project, "datasetId": dataset, "tableId": table},
                "sourceFormat": "NEWLINE_DELIMITED_JSON", "autodetect": True, "writeDisposition": "WRITE_TRUNCATE",
            }},
        }
        job = self.call("POST", jobs, json.dumps(spec).encode("utf-8")) or {}
        job_id = job["jobReference"]["jobId"]
        for _ in range(90):
            st = self.call("GET", f"{jobs}/{q(job_id, safe='')}?location={q(location, safe='')}") or {}
            status = st.get("status", {})
            if status.get("state") == "DONE":
                if status.get("errorResult"):
                    raise RuntimeError(f"BigQuery load {table} failed: {status['errorResult']}")
                return
            time.sleep(2)
        raise RuntimeError(f"BigQuery load {table} timed out")

    def count_rows(self, dataset: str, table: str, location: str) -> int:
        q = urllib.parse.quote
        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{q(self.project, safe='')}/queries"
        sql = f"SELECT COUNT(*) AS n FROM `{self.project}.{dataset}.{table}`"
        res = self.call("POST", url, json.dumps({"query": sql, "useLegacySql": False, "location": location}).encode("utf-8")) or {}
        return int(res["rows"][0]["f"][0]["v"])


def cmd_sync(args: argparse.Namespace) -> None:
    t0 = time.perf_counter()
    db_path = Path(args.db).resolve()
    if not db_path.exists():
        print(f"[SYNC_ERROR] Vault database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    project = (args.project or os.environ.get("GOOGLE_CLOUD_PROJECT", "")).strip()
    if not project:
        print("[SYNC_ERROR] Target GCP project missing. Pass --project or set GOOGLE_CLOUD_PROJECT.", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        slice_table = "slices_fts" if "slices_fts" in tables else ("slices_fallback" if "slices_fallback" in tables else "")

        hard_patterns = [p for p in SECRET_PATTERNS if p[0] != "ENV_SECRET"]
        raw_secret_hits = 0
        slice_records: list[dict] = []
        if slice_table:
            for row in conn.execute(f"SELECT path, folder_root, chunk_index, line_range, ast_summary, content FROM {slice_table}"):
                content_str = str(row[5] or "")
                for _label, pat in hard_patterns:
                    for m in pat.finditer(content_str):
                        matched = m.group(0)
                        if "Dummy" in matched or "EXAMPLE" in matched or "REDACTED" in matched:
                            continue
                        raw_secret_hits += 1
                slice_records.append({
                    "path": _normalize_export_path(row[0]), "folder_root": str(row[1] or ""),
                    "chunk_index": int(row[2]) if str(row[2]).isdigit() else 0,
                    "line_range": str(row[3] or ""), "ast_summary": str(row[4] or ""), "content": content_str,
                })
        if raw_secret_hits > 0:
            print(f"[SYNC_ABORTED_SECURITY] {raw_secret_hits} unredacted secret pattern(s) in vault slices; refusing cloud export.", file=sys.stderr)
            sys.exit(2)

        def _rows(sql: str, present: str) -> list:
            return list(conn.execute(sql)) if present in tables else []

        file_records = [{"sha256": str(r[0]), "path": _normalize_export_path(r[1]), "folder_root": str(r[2]), "ext": str(r[3]),
                         "size_bytes": int(r[4] or 0), "ast_summary": str(r[5] or ""), "is_duplicate": bool(r[6])}
                        for r in _rows("SELECT sha256, path, folder_root, ext, size_bytes, ast_summary, is_duplicate FROM files", "files")]
        link_records = [{"source_path": _normalize_export_path(r[0]), "url": str(r[1]), "category": str(r[2]), "context": str(r[3] or "")}
                        for r in _rows("SELECT source_path, url, category, context FROM links", "links")]
        vhdx_records = [{"vhdx_path": _normalize_export_path(r[0]), "entry_path": str(r[1]), "entry_size": int(r[2] or 0), "mode_note": str(r[3] or "")}
                        for r in _rows("SELECT vhdx_path, entry_path, entry_size, mode_note FROM vhdx_manifest", "vhdx_manifest")]
        zip_records = [{"zip_path": _normalize_export_path(r[0]), "folder_root": str(r[1]), "entry_path": str(r[2]),
                        "entry_size": int(r[3] or 0), "compressed_size": int(r[4] or 0)}
                       for r in _rows("SELECT zip_path, folder_root, entry_path, entry_size, compressed_size FROM zip_manifest", "zip_manifest")]
        audit_records = [{"source_path": _normalize_export_path(r[0]), "secret_type": str(r[1]), "line_number": int(r[2] or 0)}
                         for r in _rows("SELECT source_path, secret_type, line_number FROM secret_audit", "secret_audit")]
    finally:
        conn.close()

    parity = hashlib.sha256(f"{len(file_records)}:{len(slice_records)}:{len(link_records)}:{len(audit_records)}".encode("utf-8")).hexdigest()[:16]
    payloads = {"files": file_records, "slices_redacted": slice_records, "links": link_records,
                "vhdx_manifest": vhdx_records, "zip_manifest": zip_records, "secret_audit": audit_records}
    prefix = args.prefix.strip("/")
    gcs_uri = f"gs://{args.bucket}/{prefix}" if prefix else f"gs://{args.bucket}"

    with tempfile.TemporaryDirectory(prefix="vault_gcp_sync_") as tmp:
        stage = Path(tmp)
        table_meta: dict[str, dict] = {}
        total_bytes = 0
        for tname, recs in payloads.items():
            out = stage / f"{tname}.jsonl"
            with out.open("w", encoding="utf-8", newline="\n") as fh:
                for rec in recs:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            size = out.stat().st_size
            table_meta[tname] = {"rows": len(recs), "bytes": size, "sha256": hashlib.sha256(out.read_bytes()).hexdigest()[:16]}
            total_bytes += size
        manifest = {"schema": "alpha_mcp.stage0_gcp_sync.v1", "vault_name": db_path.name, "parity_sha256": parity,
                    "project": project, "location": args.location, "gcs_uri": gcs_uri,
                    "bigquery_dataset": f"{project}.{args.dataset}", "unredacted_secret_hits": 0,
                    "auth_transport": "rest_bearer_token", "tables": table_meta}
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        if not args.apply:
            print(f"[SYNC_DRY_RUN] parity={parity} bytes={total_bytes} elapsed={time.perf_counter() - t0:.2f}s")
            print(f"[DESTINATIONS] gcs={gcs_uri} bq={project}.{args.dataset} location={args.location}")
            print("[TABLES] " + " ".join(f"{k}={v['rows']}" for k, v in table_meta.items()))
            print("[GUARDRAILS] unredacted_secrets=0 binaries_excluded=True status=DRY_RUN_VERIFIED")
            return

        token, source = mint_gcp_bearer_token(args.impersonate_sa)
        gcp = GcpRest(token, project)
        gcp.ensure_bucket(args.bucket, args.location)
        for tname in payloads:
            gcp.upload_object(args.bucket, f"{prefix}/{tname}.jsonl" if prefix else f"{tname}.jsonl", (stage / f"{tname}.jsonl").read_bytes())
        gcp.upload_object(args.bucket, f"{prefix}/manifest.json" if prefix else "manifest.json", (stage / "manifest.json").read_bytes())

        verified: list[str] = []
        if not args.skip_bq:
            gcp.ensure_dataset(args.dataset, args.location)
            for tname, meta in table_meta.items():
                if meta["rows"] == 0:
                    continue
                gcp.load_table(args.bucket, prefix, args.dataset, tname, args.location)
                n = gcp.count_rows(args.dataset, tname, args.location)
                if n != meta["rows"]:
                    raise RuntimeError(f"Row-count mismatch on {tname}: local={meta['rows']} bigquery={n}")
                verified.append(f"{tname}:{n}")
        print(f"[SYNC_APPLIED] parity={parity} bytes={total_bytes} auth={source} elapsed={time.perf_counter() - t0:.2f}s")
        print(f"[DESTINATIONS] gcs={gcs_uri}/ bq={project}.{args.dataset} verified=[{', '.join(verified)}]")
        print("[GUARDRAILS] unredacted_secrets=0 binaries_excluded=True status=SYNC_COMMITTED")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stage 0 Argon-Carbon MCP Research Vault CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ing = sub.add_parser("ingest", help="Index folders, notebooks, links, .zip, and .vhdx manifests")
    p_ing.add_argument("--roots", nargs="+", required=True, help="One or more source directories to index")
    p_ing.add_argument("--db", default="./mcp_alpha_vault.sqlite3", help="Output SQLite WAL vault path")
    p_ing.add_argument("--vhdx-mode", choices=["inspect", "selective-extract", "mount-command"], default="inspect")
    p_ing.add_argument("--extract-dir", default="./vhdx_selective_stage", help="Staging path if selective-extract is used")
    p_ing.add_argument("--workers", type=int, default=0, help="Worker process count (0 = auto CPU-1)")
    p_ing.set_defaults(func=cmd_ingest)

    p_qry = sub.add_parser("query", help="BM25 FTS5 full-text search across indexed MCP research")
    p_qry.add_argument("search_query", help="FTS5 search expression (e.g., 'stdio AND server' or 'dbt')")
    p_qry.add_argument("--db", default="./mcp_alpha_vault.sqlite3")
    p_qry.add_argument("--top", type=int, default=8)
    p_qry.set_defaults(func=cmd_query)

    p_aud = sub.add_parser("audit", help="View redacted secret locations, harvested URLs, and archive manifests")
    p_aud.add_argument("--db", default="./mcp_alpha_vault.sqlite3")
    p_aud.set_defaults(func=cmd_audit)

    p_sync = sub.add_parser("sync", help="Export redacted vault JSONL + parity manifest to Cloud Storage & BigQuery over REST (default: dry-run)")
    p_sync.add_argument("--target", choices=["gcp"], default="gcp", help="Cloud sync target (default: gcp)")
    p_sync.add_argument("--db", default="./mcp_alpha_vault.sqlite3", help="Source SQLite WAL vault path")
    p_sync.add_argument("--project", default="", help="Target GCP project ID (defaults to GOOGLE_CLOUD_PROJECT)")
    p_sync.add_argument("--impersonate-sa", default="", help="Service account email to impersonate keylessly (defaults to GOOGLE_IMPERSONATE_SERVICE_ACCOUNT)")
    p_sync.add_argument("--bucket", required=True, help="Target GCS bucket name (created if absent with --apply)")
    p_sync.add_argument("--dataset", default="alpha_mcp_vault", help="Target BigQuery dataset (default: alpha_mcp_vault)")
    p_sync.add_argument("--prefix", default="stage0/latest", help="GCS object prefix (default: stage0/latest)")
    p_sync.add_argument("--location", default="us-east1", help="GCP region for GCS & BigQuery (default: us-east1)")
    p_sync.add_argument("--skip-bq", action="store_true", help="Upload to GCS only, skip BigQuery load")
    p_sync.add_argument("--apply", action="store_true", help="Execute cloud upload & BigQuery load (omit for dry-run)")
    p_sync.set_defaults(func=cmd_sync)

    return parser


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    cli_args = build_cli().parse_args()
    cli_args.func(cli_args)


if __name__ == "__main__":
    main()
