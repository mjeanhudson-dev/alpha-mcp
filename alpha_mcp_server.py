#!/usr/bin/env python3
"""alpha_mcp_server.py - zero-dependency MCP server (stdio JSON-RPC 2.0) over the Stage 0 research vault.

Tools are read-only. Every tool result passes through a 13-pattern credential sieve.
Vault path: ALPHA_MCP_VAULT_DB or ./mcp_alpha_vault.sqlite3 (build it with mcp_carbon_ingest.py ingest).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SERVER_NAME, SERVER_VERSION = "alpha-mcp", "1.1.0"
MAX_SLICE_LINES = 160
HOME = Path.home()

REDACTIONS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("BEARER_TOKEN", re.compile(r"(Bearer\s+)[A-Za-z0-9._\-=/+]+", re.I), r"\1[REDACTED:BEARER_TOKEN]"),
    ("SENTRY_TOKEN", re.compile(r"(sntrys_)[A-Za-z0-9._\-=/+]+", re.I), r"\1[REDACTED:SENTRY_TOKEN]"),
    ("GOOGLE_API_KEY", re.compile(r"(AIza)[0-9A-Za-z._\-]{10,}"), r"\1[REDACTED:GOOGLE_API_KEY]"),
    ("GOOGLE_OAUTH_TOKEN", re.compile(r"AQ\.Ab8[0-9A-Za-z._\-]{15,}|ya29\.[0-9A-Za-z_\-]{20,}"), "[REDACTED:GOOGLE_OAUTH_TOKEN]"),
    ("GOOGLE_OAUTH_SECRET", re.compile(r"(GOCSPX-)[A-Za-z0-9_\-]{12,}"), r"\1[REDACTED:GOOGLE_OAUTH_SECRET]"),
    ("ANTHROPIC_KEY", re.compile(r"(sk-ant-)[A-Za-z0-9._\-]+", re.I), r"\1[REDACTED:ANTHROPIC_KEY]"),
    ("OPENAI_KEY", re.compile(r"\b(sk-(?:proj-|svcacct-)?)[A-Za-z0-9_\-]{20,}"), r"\1[REDACTED:OPENAI_KEY]"),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{30,}"), "[REDACTED:GITHUB_TOKEN]"),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:AWS_ACCESS_KEY]"),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED:SLACK_TOKEN]"),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), "[REDACTED:STRIPE_KEY]"),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "[REDACTED:PRIVATE_KEY]"),
    ("ENV_SECRET", re.compile(r"(?im)^([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*)(['\"]?[^\s#'\"]{8,}['\"]?)"), r"\1[REDACTED:ENV_SECRET]"),
)
SECRET_NAMES = {".env", "id_rsa", "id_ed25519", "credentials.json", "application_default_credentials.json"}
SECRET_SUFFIXES = (".pem", ".key", ".kdbx", ".p12", ".pfx")
SECRET_HINTS = ("oauth_client", "oauth_token", "client_secret_", "service-account", "service_account")


def redact(text: Any) -> str:
    out = str(text)
    for _label, pat, repl in REDACTIONS:
        out = pat.sub(repl, out)
    return out


def is_secret_path(path: str | Path) -> bool:
    p = Path(path)
    name = p.name.lower()
    return (
        name in SECRET_NAMES or name.startswith(".env.") or name.endswith(SECRET_SUFFIXES)
        or any(h in name for h in SECRET_HINTS)
    )


def public_path(raw: str) -> str:
    home = str(HOME)
    text = str(raw or "")
    return ("~" + text[len(home):]).replace("\\", "/") if text.lower().startswith(home.lower()) else text.replace("\\", "/")


def open_vault(db_path: str | None) -> tuple[sqlite3.Connection | None, str]:
    target = Path(db_path or os.environ.get("ALPHA_MCP_VAULT_DB", "") or "./mcp_alpha_vault.sqlite3").expanduser().resolve()
    if not target.exists():
        return None, f"Vault not found at {public_path(str(target))}; run: python mcp_carbon_ingest.py ingest --roots <dir>"
    return sqlite3.connect(f"file:{target.as_posix()}?mode=ro", uri=True, timeout=3.0), ""


def tool_fts_query(query: str, top_k: int = 5, db_path: str | None = None) -> dict:
    q = (query or "").strip()
    if not q:
        return {"status": "ERROR", "error": "query must be non-empty"}
    conn, err = open_vault(db_path)
    if conn is None:
        return {"status": "ERROR", "error": err}
    try:
        sql = ("SELECT path, folder_root, line_range, ast_summary, snippet(slices_fts, 5, '>>>', '<<<', ' ... ', 28) "
               "FROM slices_fts WHERE slices_fts MATCH ? ORDER BY rank LIMIT ?")
        k = max(1, min(int(top_k), 20))
        try:
            rows = conn.execute(sql, (q, k)).fetchall()
        except sqlite3.OperationalError:
            rows = conn.execute(sql, ('"' + q.replace('"', '""') + '"', k)).fetchall()
        hits = [{"path": public_path(r[0]), "folder_root": r[1], "line_range": r[2],
                 "ast_summary": " | ".join(str(r[3] or "").splitlines()[:3]), "snippet": str(r[4] or "").strip()} for r in rows]
        return {"status": "OK", "query": q, "hit_count": len(hits), "hits": hits}
    finally:
        conn.close()


def tool_manifest_lookup(scope: str = "summary", limit: int = 15, db_path: str | None = None) -> dict:
    conn, err = open_vault(db_path)
    if conn is None:
        return {"status": "ERROR", "error": err}
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        count = lambda t: int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]) if t in tables else 0
        lim = max(1, min(int(limit), 50))
        out: dict[str, Any] = {"status": "OK", "scope": scope, "counts": {
            "files": count("files"), "slices": count("slices_fts") or count("slices_fallback"), "links": count("links"),
            "vhdx_entries": count("vhdx_manifest"), "zip_entries": count("zip_manifest"), "secret_audit_hits": count("secret_audit")}}
        if scope == "vhdx" and "vhdx_manifest" in tables:
            out["rows"] = [{"vhdx": public_path(r[0]), "entry": r[1], "size_bytes": r[2]} for r in conn.execute(
                "SELECT vhdx_path, entry_path, entry_size FROM vhdx_manifest LIMIT ?", (lim,))]
        elif scope == "zip" and "zip_manifest" in tables:
            out["rows"] = [{"zip": public_path(r[0]), "entries": r[1], "uncompressed_bytes": r[2]} for r in conn.execute(
                "SELECT zip_path, COUNT(*), COALESCE(SUM(entry_size), 0) FROM zip_manifest GROUP BY zip_path ORDER BY COUNT(*) DESC LIMIT ?", (lim,))]
        elif scope == "links" and "links" in tables:
            out["rows"] = [{"category": r[0], "url": r[1]} for r in conn.execute("SELECT category, url FROM links LIMIT ?", (lim,))]
        elif scope == "secret_audit" and "secret_audit" in tables:
            out["rows"] = [{"source": public_path(r[0]), "secret_type": r[1], "count": r[2]} for r in conn.execute(
                "SELECT source_path, secret_type, COUNT(*) FROM secret_audit GROUP BY source_path, secret_type LIMIT ?", (lim,))]
        return out
    finally:
        conn.close()


_SLICE_PARITY: dict[str, str] = {}


def tool_ast_slice(filepath: str, start_line: int = 1, end_line: int = MAX_SLICE_LINES, force_read: bool = False) -> dict:
    p = Path(filepath).expanduser()
    if is_secret_path(p):
        return {"status": "ERROR", "code": "SECRET_PATH_AIRLOCK_DENY", "error": f"Blocked protected file: {public_path(str(p))}"}
    if not p.is_file():
        return {"status": "ERROR", "error": f"File not found: {public_path(str(p))}"}
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(start_line))
    end = min(len(lines), start + MAX_SLICE_LINES - 1, max(start, int(end_line)))
    chunk = lines[start - 1:end]
    digest = hashlib.sha256("\n".join(chunk).encode("utf-8")).hexdigest()
    key = f"{p.resolve()}:{start}:{end}"
    if _SLICE_PARITY.get(key) == digest and not force_read:
        return {"status": "SHA256_PARITY_HIT", "lines": f"L{start}-L{end}", "sha256": digest[:16]}
    _SLICE_PARITY[key] = digest
    return {"status": "SLICE_FETCHED", "lines": f"L{start}-L{end}", "total_lines": len(lines), "sha256": digest[:16],
            "slice": "\n".join(f"{i:4d} | {ln}" for i, ln in enumerate(chunk, start=start))}


def tool_precompensate(raw_stdout: str, command_label: str = "cli") -> dict:
    est = max(1, len(raw_stdout) // 4)
    if est <= 500:
        return {"status": "PASSTHROUGH_CLEAN", "delta": raw_stdout.strip(), "raw_tokens": est}
    fault = re.compile(r"(error|exception|failed|traceback|assert|fatal|critical|fault)", re.I)
    kept, seen, used = [], set(), 0
    for i, ln in enumerate(raw_stdout.splitlines(), 1):
        norm = re.sub(r"\s+", " ", ln.strip())[:160]
        if norm and fault.search(norm) and norm not in seen:
            seen.add(norm)
            item = f"L{i:04d}: {norm}"
            if used + len(item) > 900:
                break
            kept.append(item)
            used += len(item) + 1
    delta = f"[DELTA cmd={command_label} raw_tokens={est}]\n" + "\n".join(kept or [f"TAIL: {t[:140]}" for t in raw_stdout.splitlines()[-6:]])
    return {"status": "TRUNCATED", "raw_tokens": est, "delta_tokens": max(1, len(delta) // 4), "delta": delta}


def tool_edge_route(task_type: str = "thermal_audit", phone_temp_c: float = 34.0, vram_used_gb: float = 3.5) -> dict:
    t = max(0.0, min(1.0, (float(phone_temp_c) - 32.0) / 10.0))
    stress = round(t * t * t * (t * (t * 6 - 15) + 10), 4)
    ceiling = 7.08
    node = "WORKSTATION_GPU" if float(vram_used_gb) <= ceiling else "OVERFLOW_ESCALATE"
    return {"status": "ROUTED", "task_type": task_type, "thermal_stress": stress, "ramp_band_c": [32.0, 42.0],
            "vram": {"used_gb": float(vram_used_gb), "ceiling_gb": ceiling, "within_budget": float(vram_used_gb) <= ceiling},
            "target_node": node}


def tool_vertex_query(prompt: str, model: str = "gemini-4-carbon", max_tokens: int = 512) -> dict:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    sa = os.environ.get("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "").strip()
    if not project or not sa:
        return {"status": "NOT_CONFIGURED", "hint": "Set GOOGLE_CLOUD_PROJECT and GOOGLE_IMPERSONATE_SERVICE_ACCOUNT (keyless impersonation via gcloud)."}
    import shutil
    import subprocess
    gcloud = shutil.which("gcloud.cmd") or shutil.which("gcloud")
    if not gcloud:
        return {"status": "ERROR", "error": "gcloud CLI not found"}
    tok = subprocess.run([gcloud, "auth", "print-access-token", f"--impersonate-service-account={sa}"],
                         capture_output=True, text=True, timeout=30, check=False).stdout.strip()
    if len(tok) < 20:
        return {"status": "ERROR", "error": "token mint failed; check serviceAccountTokenCreator permission"}
    url = (f"https://aiplatform.googleapis.com/v1/projects/{urllib.parse.quote(project)}/locations/global"
           f"/publishers/google/models/{urllib.parse.quote(model)}:generateContent")
    body = json.dumps({"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                       "generationConfig": {"maxOutputTokens": max(64, min(int(max_tokens), 2048))}}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {tok}", "X-Goog-User-Project": project, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"status": "ERROR", "error": f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:200]}"}
    parts = (((data.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
    return {"status": "OK", "model": model, "text": "".join(p.get("text", "") for p in parts).strip()}


def _schema(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


_ANN = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
TOOLS: list[dict] = [
    {"name": "stage0_vault_fts_query", "description": "BM25 FTS5 search over the redacted research vault.",
     "annotations": {**_ANN, "title": "Vault FTS Query"},
     "inputSchema": _schema({"query": {"type": "string"}, "top_k": {"type": "integer", "default": 5}, "db_path": {"type": "string"}}, ["query"])},
    {"name": "stage0_vault_manifest_lookup", "description": "Inspect vault counts and VHDX/ZIP/link/secret-audit manifests (metadata only).",
     "annotations": {**_ANN, "title": "Vault Manifest Lookup"},
     "inputSchema": _schema({"scope": {"type": "string", "enum": ["summary", "vhdx", "zip", "links", "secret_audit"], "default": "summary"},
                             "limit": {"type": "integer", "default": 15}, "db_path": {"type": "string"}})},
    {"name": "stage0_ast_slice_and_parity", "description": "Read a file as a <=160-line slice with SHA-256 dedup; credential files are blocked.",
     "annotations": {**_ANN, "title": "Slice With Secret Airlock"},
     "inputSchema": _schema({"filepath": {"type": "string"}, "start_line": {"type": "integer", "default": 1},
                             "end_line": {"type": "integer", "default": 160}, "force_read": {"type": "boolean", "default": False}}, ["filepath"])},
    {"name": "precompensate_stdout_delta", "description": "Compress noisy logs (>500 tokens) into a fault-only delta.",
     "annotations": {**_ANN, "title": "Stdout Delta Compressor"},
     "inputSchema": _schema({"raw_stdout": {"type": "string"}, "command_label": {"type": "string", "default": "cli"}}, ["raw_stdout"])},
    {"name": "tandem_edge_route", "description": "Thermal (quintic 32-42C ramp) and VRAM headroom router for local edge tasks.",
     "annotations": {**_ANN, "title": "Edge Thermal/VRAM Router"},
     "inputSchema": _schema({"task_type": {"type": "string", "default": "thermal_audit"}, "phone_temp_c": {"type": "number", "default": 34.0},
                             "vram_used_gb": {"type": "number", "default": 3.5}})},
    {"name": "vertex_keyless_query", "description": "Optional Vertex AI call using keyless service-account impersonation.",
     "annotations": {**_ANN, "title": "Keyless Vertex Query", "openWorldHint": True},
     "inputSchema": _schema({"prompt": {"type": "string"}, "model": {"type": "string", "default": "gemini-4-carbon"},
                             "max_tokens": {"type": "integer", "default": 512}}, ["prompt"])},
]
DISPATCH = {"stage0_vault_fts_query": tool_fts_query, "stage0_vault_manifest_lookup": tool_manifest_lookup,
            "stage0_ast_slice_and_parity": tool_ast_slice, "precompensate_stdout_delta": tool_precompensate,
            "tandem_edge_route": tool_edge_route, "vertex_keyless_query": tool_vertex_query}


def handle(msg: dict) -> dict | None:
    method, mid, params = msg.get("method", ""), msg.get("id"), msg.get("params") or {}
    if mid is None and method.startswith("notifications/"):
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": params.get("protocolVersion") or "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        fn = DISPATCH.get(params.get("name"))
        if fn is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Unknown tool: {params.get('name')}"}}
        try:
            res = fn(**(params.get("arguments") or {}))
        except Exception as exc:
            res = {"status": "ERROR", "error": str(exc)}
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": redact(json.dumps(res, indent=2))}],
                "isError": isinstance(res, dict) and res.get("status") == "ERROR"}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def selftest() -> int:
    def call(name: str, args: dict) -> dict:
        resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
        return resp["result"]
    assert len(TOOLS) == 6 and all(t["annotations"]["readOnlyHint"] for t in TOOLS)
    assert call("stage0_ast_slice_and_parity", {"filepath": str(HOME / ".env")})["isError"] is True
    first = json.loads(call("stage0_ast_slice_and_parity", {"filepath": __file__, "end_line": 20})["content"][0]["text"])
    again = json.loads(call("stage0_ast_slice_and_parity", {"filepath": __file__, "end_line": 20})["content"][0]["text"])
    assert first["status"] == "SLICE_FETCHED" and again["status"] == "SHA256_PARITY_HIT"
    noisy = "\n".join([f"[INFO] trace {i}" for i in range(300)] + ["AssertionError: line 42 fault"])
    assert json.loads(call("precompensate_stdout_delta", {"raw_stdout": noisy})["content"][0]["text"])["delta_tokens"] <= 300
    edge = json.loads(call("tandem_edge_route", {"phone_temp_c": 37.0, "vram_used_gb": 3.0})["content"][0]["text"])
    assert edge["status"] == "ROUTED" and edge["vram"]["within_budget"]
    probe = redact("Bearer abc123 GOCSPX-" + "DummyDummyDummy01 ya29." + "D" * 24 + " sk-ant-" + "D" * 24 + " AKIA" + "0" * 16)
    assert "abc123" not in probe and "DummyDummyDummy01" not in probe and "AKIA" + "0" * 16 not in probe
    assert len(REDACTIONS) == 13
    print(json.dumps({"status": "ALL_SELFTESTS_PASSED", "tools": len(TOOLS), "redaction_patterns": len(REDACTIONS)}))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Alpha MCP stdio server over the Stage 0 research vault")
    ap.add_argument("--transport", choices=["stdio"], default="stdio")
    ap.add_argument("--selftest", action="store_true", help="Run built-in checks and exit")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}}) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(msg) if isinstance(msg, dict) else None
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
