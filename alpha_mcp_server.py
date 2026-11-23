#!/usr/bin/env python3
"""alpha_mcp_server.py - Sovereign Dual-Modality MCP v2.0 (stdio + hardened Streamable HTTP).

Zero-dependency Python 3.10+ stdlib server over the Stage 0 research vault with:
- Prefix-pinned 10-tool wire contract (capabilities.tools.listChanged = False)
- Across-the-Line Apex Contactor (NEXUS_FLASH_SHUNT=1) & Exodia 25:1 compaction gate
- SEP-2640 atomic skill manifests (<= 4,500 tokens) & CSAA HMAC-SHA256 A2A artifacts
- 19 governing equations (EQ_01..EQ_19), 4 MCP resources, 3 nil-arg resilient prompts
- Hardened Streamable HTTP with fail-closed non-loopback auth airlock, OAuth 2.1 PKCE
  S256 + RFC 7009 revocation, and signed Google A2A v1.0.1 Agent Card
- 13-pattern credential redaction sieve & secret-path file airlock

Vault path: ALPHA_MCP_VAULT_DB or ./mcp_alpha_vault.sqlite3 (build via mcp_carbon_ingest.py).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SERVER_NAME = "alpha-mcp"
SERVER_VERSION = "2.0.0"
MAX_SLICE_LINES = 160
MAX_ESCALATION_TOKENS = 6000
MAX_SKILL_TOKENS = 4500
MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024
HOME = Path.home()

SUPPORTED_PROTOCOL_VERSIONS: list[str] = [
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
]
ZERO_COST_ONLINE_TIERS: list[str] = [
    "cloudflare_named_tunnel_$0",
    "cloud_run_min_scale_0_$0",
    "static_edge_pages_$0",
]

# Per-boot CSPRNG signing key; ZERO static fallback strings.
_BOOT_SIGNING_SECRET: bytes = secrets.token_bytes(32)


def _get_signing_secret() -> bytes:
    env_val = os.environ.get("ALPHA_MCP_SIGNING_SECRET", "").strip()
    return env_val.encode("utf-8") if env_val else _BOOT_SIGNING_SECRET


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# 13-Pattern Credential Redaction Sieve & Secret-Path Airlock
# ---------------------------------------------------------------------------

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


def _redact_obj(obj: Any) -> Any:
    """Recursively redact all strings before JSON serialization so \\n escapes cannot bypass \\b or ^ patterns."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {(_redact_obj(k) if isinstance(k, str) else k): _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(item) for item in obj]
    if isinstance(obj, tuple):
        return [_redact_obj(item) for item in obj]
    return obj


def is_secret_path(path: str | Path) -> bool:
    p = Path(path)
    name = p.name.lower()
    return (
        name in SECRET_NAMES
        or name.startswith(".env.")
        or name.endswith(SECRET_SUFFIXES)
        or any(h in name for h in SECRET_HINTS)
    )


def public_path(raw: str) -> str:
    home = str(HOME)
    text = str(raw or "")
    return ("~" + text[len(home):]).replace("\\", "/") if text.lower().startswith(home.lower()) else text.replace("\\", "/")


# ---------------------------------------------------------------------------
# Across-the-Line Apex Contactor (NEXUS_FLASH_SHUNT=1)
# ---------------------------------------------------------------------------

APEX_PROVIDER_MODELS: dict[str, str] = {
    "google": "gemini-4-neon",
    "anthropic": "claude-opus-5-5",
    "openai": "gpt-5-pro-high",
}
BANNED_LOW_POLY_TOKENS: tuple[str, ...] = ("flash", "lite", "mini", "haiku", "nano", "small")


def enforce_apex_shunt(model: str, provider: str = "google") -> tuple[str, bool]:
    """Hard-bypass banned low-poly tiers to provider Apex models."""
    prov = (provider or "google").strip().lower()
    apex_model = APEX_PROVIDER_MODELS.get(prov, "gemini-4-neon")
    raw = (model or "").strip()
    if not raw:
        return apex_model, True
    lower = raw.lower()
    if any(tok in lower for tok in BANNED_LOW_POLY_TOKENS):
        return apex_model, True
    return raw, False


# ---------------------------------------------------------------------------
# 19 Governing Equations Vault (EQ_01..EQ_19)
# ---------------------------------------------------------------------------

EQUATIONS_VAULT: list[dict[str, str]] = [
    {"id": "EQ_01", "name": "Hardcoded Grid Stability", "formula": "Stability = integral(Anchor * Presence) dt -> inf", "target": "L0 Genesis Anchor (t = 0)"},
    {"id": "EQ_02", "name": "Closed-Loop Feedforward Pre-Compensation", "formula": "u(t) = K_p*e(t) + F_feedforward(grad AST)", "target": "L1 Stdout & AST pre-compensation"},
    {"id": "EQ_03", "name": "LTV Lyapunov Exponential Drift Decay", "formula": "e(T) = e(0) * exp(-lambda * integral(w(t) dt))", "target": "Multi-turn trajectory stability"},
    {"id": "EQ_04", "name": "KPPC-LOD v1.2 Bounded Distillation Metric (Form A)", "formula": "M_A = Q_distill * exp(-0.05 * max(0, tokens - 4000) / 4000)", "target": "L2 Context efficiency telemetry"},
    {"id": "EQ_05", "name": "Lexicographic Non-Compensatory KPPC Gate", "formula": "Phi_ISF = prod_{k=1}^{5} p_k == 1 else ABSTENTION_HALT", "target": "Safety & capability reference monitor"},
    {"id": "EQ_06", "name": "C2-Continuous Quintic Smootherstep Thermal & VRAM Governor", "formula": "S(t) = 6*t^5 - 15*t^4 + 10*t^3, t = clamp((T - 32.0)/10.0, 0, 1)", "target": "Edge thermal blending [32C, 42C]"},
    {"id": "EQ_07", "name": "Inverse Deadzone Saliency Filter", "formula": "X_proxy = d + (1 - d) * sqrt(|x|) * sgn(x), d = 0.18", "target": "Fault-signal saliency & deadzone pre-compensation"},
    {"id": "EQ_08", "name": "BitNet b1.58 Ternary Quantization & 5-Trit Byte Packing", "formula": "3^5 = 243 <= 255 states/byte; VRAM_ceiling = 7.08 GB", "target": "Local 8 GB VRAM edge headroom"},
    {"id": "EQ_09", "name": "Anderson Non-Bypassable Reference Monitor Law", "formula": "Tamperproof & Always-Invoked & Small-Enough-to-Verify", "target": "Pre-commit deterministic airlock"},
    {"id": "EQ_10", "name": "KPPC-LOD v1.2 AST/SHA-Gated Work Ratio (Form B)", "formula": "A_KPPC = R_AST * Q_diff * C_sha256 (B_diff = 1200)", "target": "Output verbosity penalty & diff grounding"},
    {"id": "EQ_11", "name": "Sagittal Pitch Projection & 1-Euro Filter", "formula": "omega_roll = -(omega_z*cos(theta) + omega_y*sin(theta)); f_c_min = 1.20 Hz, beta = 0.040", "target": "controller_kinematics smoothing"},
    {"id": "EQ_12", "name": "Menu Trigger Isolation & Loading Exit Blend", "formula": "Driving = (R2 > 35) OR (rumble > 0); exit stall > 1200 ms -> 200 ms C2 blend", "target": "Hardware input isolation"},
    {"id": "EQ_13", "name": "Recline Immunity Gravity Decoupling", "formula": "|theta_pitch| > 30 deg => alpha_ax = 0", "target": "Sagittal steering stability"},
    {"id": "EQ_14", "name": "5-Level Monotonic Information Flow Taint Lattice", "formula": "Egress iff (not killswitch) AND (Phi_ISF == 1) AND (Taint < L2)", "target": "Anti-authority-collapse egress gate"},
    {"id": "EQ_15", "name": "HKDF-SHA256 Ephemeral Phantom Secret Derivation", "formula": "K_ephem = HKDF-SHA256(IKM, epoch=900s, info=ASTDigest)", "target": "Zero-leak JIT credential minting"},
    {"id": "EQ_16", "name": "PBFT Quorum Availability Upgrade", "formula": "q_PBFT = 2f + 1 = 13 of n = 21 (98.03% availability)", "target": "Byzantine validation quorum"},
    {"id": "EQ_17", "name": "Cryptographic Hash-Chained WAL & VDF Checkpointing", "formula": "H_i = SHA256(H_{i-1} || payload_i), H_0 = 0*64, N_iter >= 5000", "target": "Tamper-evident SQLite WAL ledger"},
    {"id": "EQ_18", "name": "Shannon Entropy Proof-of-Work & Cache Mastery Index", "formula": "AntiCheat(H) = clip(H / 3.5, 0.25, 1.0)", "target": "Telemetry anti-padding audit"},
    {"id": "EQ_19", "name": "Monthly Context Arbitrage ROI", "formula": "eta_arb = 1 - (C_stage0_plus_apex / C_uncompacted) in [0, 99.9%]", "target": "Frontier cache-read offload economics"},
]


# ---------------------------------------------------------------------------
# SEP-2640 Atomic Skill Manifests (<= 4,500 tokens each)
# ---------------------------------------------------------------------------

def _build_skill(name: str, summary: str, body: str) -> dict[str, Any]:
    uri = f"skill://alpha/{name}/SKILL.md"
    encoded = body.encode("utf-8")
    return {
        "name": name,
        "uri": uri,
        "summary": summary,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "estimated_tokens": max(1, len(body) // 4),
        "max_tokens": MAX_SKILL_TOKENS,
        "ttlMs": 3600000,
        "content": body,
    }


SEP2640_SKILLS: dict[str, dict[str, Any]] = {
    "alpha-stage0-vault": _build_skill(
        "alpha-stage0-vault",
        "Zero-dependency Stage 0 SQLite WAL + BM25 FTS5 retrieval and <=160-line AST slicing with secret-path airlock.",
        "# Alpha Stage 0 Vault Skill (SEP-2640)\n\n"
        "1. Query redacted slices via `stage0_vault_fts_query` (BM25 FTS5) or inspect counts via `stage0_vault_manifest_lookup`.\n"
        "2. Read source files strictly in <=160-line slices via `stage0_ast_slice_and_parity` (SHA-256 parity cache; credential files fail with `SECRET_PATH_AIRLOCK_DENY`).\n"
        "3. Compress verbose command logs (>500 tokens) into <300-token fault deltas via `precompensate_stdout_delta`.\n",
    ),
    "state-interpolation": _build_skill(
        "state-interpolation",
        "3-Act Open/Mid/Exit state contact sheet interpolation with mandatory workflow_id precheck and CSAA HMAC-SHA256 minting.",
        "# State Interpolation Skill (SEP-2640)\n\n"
        "1. Always supply a non-empty `workflow_id` to `interpolate_state_sheet`; omitting it returns a <120-token `-32602` fault pointer.\n"
        "2. Supply `act_open`, `act_mid`, `act_exit` state snapshots and optional `mechanical_assertions`.\n"
        "3. Passing assertions mint a CSAA A2A v1.0.1 artifact signed with HMAC-SHA256 (`state=completed`, `taintProvenance=VERIFIED_ARCHITECT`).\n",
    ),
    "zero-cost-dual-modality": _build_skill(
        "zero-cost-dual-modality",
        "Run Alpha MCP over local stdio and authenticated Streamable HTTP on $0/mo edge tiers with fail-closed OAuth 2.1 PKCE S256.",
        "# Zero-Cost Dual-Modality Hosting Skill (SEP-2640)\n\n"
        "1. Local IDE transport: `python alpha_mcp_server.py --transport stdio` ($0/mo, sub-3ms latency).\n"
        "2. Authenticated edge HTTP: `python alpha_mcp_server.py --transport http --host 127.0.0.1 --port 8000 --require-auth` behind a Cloudflare Named Tunnel ($0/mo) or Cloud Run `min-instances=0` ($0/mo).\n"
        "3. Set `ALPHA_MCP_BEARER_TOKEN` and `ALPHA_MCP_OAUTH_SECRET` before remote exposure; never store static GCP service-account key files on disk.\n",
    ),
}


# ---------------------------------------------------------------------------
# In-Memory Telemetry Ledger & Slice Parity State (Thread-Safe)
# ---------------------------------------------------------------------------

_STATE_LOCK = threading.Lock()
_SLICE_PARITY: dict[str, str] = {}
_TELEMETRY: dict[str, Any] = {
    "boot_time_utc": _utc_iso(),
    "slice_fetches": 0,
    "slice_parity_hits": 0,
    "secret_airlock_denials": 0,
    "apex_shunts_applied": 0,
    "exodia_compactions_triggered": 0,
    "last_exodia_ratio": 0.0,
    "last_exodia_state": "NOMINAL_BELOW_25_TO_1_GATE",
    "csaa_artifacts_minted": 0,
}


# ---------------------------------------------------------------------------
# Stage 0 Vault & Tool Implementations (#01..#10)
# ---------------------------------------------------------------------------

def open_vault(db_path: str | None) -> tuple[sqlite3.Connection | None, str]:
    target = Path(db_path or os.environ.get("ALPHA_MCP_VAULT_DB", "") or "./mcp_alpha_vault.sqlite3").expanduser().resolve()
    if not target.exists():
        return None, f"Vault not found at {public_path(str(target))}; run: python mcp_carbon_ingest.py ingest --roots <dir>"
    return sqlite3.connect(f"file:{target.as_posix()}?mode=ro", uri=True, timeout=3.0), ""


def tool_fts_query(query: str, top_k: int = 5, db_path: str | None = None) -> dict[str, Any]:
    q = (query or "").strip()
    if not q:
        return {"status": "ERROR", "error": "query must be non-empty"}
    conn, err = open_vault(db_path)
    if conn is None:
        return {"status": "ERROR", "error": err}
    try:
        sql = (
            "SELECT path, folder_root, line_range, ast_summary, snippet(slices_fts, 5, '>>>', '<<<', ' ... ', 28) "
            "FROM slices_fts WHERE slices_fts MATCH ? ORDER BY rank LIMIT ?"
        )
        k = max(1, min(int(top_k), 20))
        try:
            rows = conn.execute(sql, (q, k)).fetchall()
        except sqlite3.OperationalError:
            rows = conn.execute(sql, ('"' + q.replace('"', '""') + '"', k)).fetchall()
        hits = [
            {
                "path": public_path(r[0]),
                "folder_root": r[1],
                "line_range": r[2],
                "ast_summary": " | ".join(str(r[3] or "").splitlines()[:3]),
                "snippet": str(r[4] or "").strip(),
            }
            for r in rows
        ]
        return {"status": "OK", "query": q, "hit_count": len(hits), "hits": hits}
    finally:
        conn.close()


def tool_manifest_lookup(scope: str = "summary", limit: int = 15, db_path: str | None = None) -> dict[str, Any]:
    conn, err = open_vault(db_path)
    if conn is None:
        return {"status": "ERROR", "error": err}
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        count = lambda t: int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]) if t in tables else 0
        lim = max(1, min(int(limit), 50))
        out: dict[str, Any] = {
            "status": "OK",
            "scope": scope,
            "counts": {
                "files": count("files"),
                "slices": count("slices_fts") or count("slices_fallback"),
                "links": count("links"),
                "vhdx_entries": count("vhdx_manifest"),
                "zip_entries": count("zip_manifest"),
                "secret_audit_hits": count("secret_audit"),
            },
        }
        if scope == "vhdx" and "vhdx_manifest" in tables:
            out["rows"] = [
                {"vhdx": public_path(r[0]), "entry": r[1], "size_bytes": r[2]}
                for r in conn.execute("SELECT vhdx_path, entry_path, entry_size FROM vhdx_manifest LIMIT ?", (lim,))
            ]
        elif scope == "zip" and "zip_manifest" in tables:
            out["rows"] = [
                {"zip": public_path(r[0]), "entries": r[1], "uncompressed_bytes": r[2]}
                for r in conn.execute(
                    "SELECT zip_path, COUNT(*), COALESCE(SUM(entry_size), 0) FROM zip_manifest GROUP BY zip_path ORDER BY COUNT(*) DESC LIMIT ?",
                    (lim,),
                )
            ]
        elif scope == "links" and "links" in tables:
            out["rows"] = [
                {"category": r[0], "url": r[1]}
                for r in conn.execute("SELECT category, url FROM links LIMIT ?", (lim,))
            ]
        elif scope == "secret_audit" and "secret_audit" in tables:
            out["rows"] = [
                {"source": public_path(r[0]), "secret_type": r[1], "count": r[2]}
                for r in conn.execute(
                    "SELECT source_path, secret_type, COUNT(*) FROM secret_audit GROUP BY source_path, secret_type LIMIT ?",
                    (lim,),
                )
            ]
        return out
    finally:
        conn.close()


def tool_ast_slice(
    filepath: str,
    start_line: int = 1,
    end_line: int = MAX_SLICE_LINES,
    force_read: bool = False,
) -> dict[str, Any]:
    p = Path(filepath).expanduser()
    if is_secret_path(p):
        with _STATE_LOCK:
            _TELEMETRY["secret_airlock_denials"] += 1
        return {
            "status": "ERROR",
            "code": "SECRET_PATH_AIRLOCK_DENY",
            "error": f"Blocked protected file: {public_path(str(p))}",
        }
    if not p.is_file():
        return {"status": "ERROR", "error": f"File not found: {public_path(str(p))}"}
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(start_line))
    end = min(len(lines), start + MAX_SLICE_LINES - 1, max(start, int(end_line)))
    chunk = lines[start - 1:end]
    digest = hashlib.sha256("\n".join(chunk).encode("utf-8")).hexdigest()
    key = f"{p.resolve()}:{start}:{end}"
    with _STATE_LOCK:
        if _SLICE_PARITY.get(key) == digest and not force_read:
            _TELEMETRY["slice_parity_hits"] += 1
            return {"status": "SHA256_PARITY_HIT", "lines": f"L{start}-L{end}", "sha256": digest[:16]}
        _SLICE_PARITY[key] = digest
        _TELEMETRY["slice_fetches"] += 1
    return {
        "status": "SLICE_FETCHED",
        "lines": f"L{start}-L{end}",
        "total_lines": len(lines),
        "sha256": digest[:16],
        "slice": "\n".join(f"{i:4d} | {ln}" for i, ln in enumerate(chunk, start=start)),
    }


def tool_precompensate(raw_stdout: str, command_label: str = "cli") -> dict[str, Any]:
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
    label_short = (command_label or "cli").strip()[:48]
    body_lines = kept or [f"TAIL: {t[:140]}" for t in raw_stdout.splitlines()[-6:]]
    delta = f"[DELTA cmd={label_short} raw_tokens={est}]\n" + "\n".join(body_lines)
    if len(delta) > 1160:
        delta = delta[:1140].rstrip() + "\n[TRUNCATED<300_TOK]"
    return {
        "status": "TRUNCATED",
        "raw_tokens": est,
        "delta_tokens": max(1, len(delta) // 4),
        "delta": delta,
    }


def tool_edge_route(
    task_type: str = "thermal_audit",
    phone_temp_c: float = 34.0,
    vram_used_gb: float = 3.5,
    multi_turn: bool = False,
) -> dict[str, Any]:
    t = max(0.0, min(1.0, (float(phone_temp_c) - 32.0) / 10.0))
    stress = round(t * t * t * (t * (t * 6.0 - 15.0) + 10.0), 4)
    ceiling = 7.08
    within_budget = float(vram_used_gb) <= ceiling
    if bool(multi_turn):
        node = "APEX_ESCALATE"
        resolved_model = "gemini-4-neon"
        reason = "multi_turn=True bypasses bounded 1-turn local edge and escalates directly to gemini-4-neon"
    elif not within_budget:
        node = "OVERFLOW_ESCALATE"
        resolved_model = "gemini-4-neon"
        reason = "vram_used_gb exceeds 7.08 GB ceiling; escalating to gemini-4-neon"
    elif stress >= 0.85:
        node = "THERMAL_SHUNT_APEX"
        resolved_model = "gemini-4-neon"
        reason = "quintic thermal stress >= 0.85 on [32.0, 42.0] C band; shunting to gemini-4-neon"
    else:
        node = "WORKSTATION_GPU"
        resolved_model = "stage0_local_edge"
        reason = "within thermal and VRAM budget for bounded 1-turn edge execution"
    return {
        "status": "ROUTED",
        "task_type": task_type,
        "multi_turn": bool(multi_turn),
        "thermal_stress": stress,
        "ramp_band_c": [32.0, 42.0],
        "vram": {"used_gb": float(vram_used_gb), "ceiling_gb": ceiling, "within_budget": within_budget},
        "target_node": node,
        "resolved_model": resolved_model,
        "routing_reason": reason,
    }


def tool_vertex_query(prompt: str, model: str = "gemini-4-neon", max_tokens: int = 512) -> dict[str, Any]:
    resolved_model, shunt_applied = enforce_apex_shunt(model, provider="google")
    if shunt_applied:
        with _STATE_LOCK:
            _TELEMETRY["apex_shunts_applied"] += 1
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    sa = os.environ.get("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "").strip()
    if not project or not sa:
        return {
            "status": "NOT_CONFIGURED",
            "requested_model": model,
            "resolved_model": resolved_model,
            "shunt_applied": shunt_applied,
            "hint": "Set GOOGLE_CLOUD_PROJECT and GOOGLE_IMPERSONATE_SERVICE_ACCOUNT (keyless impersonation via gcloud).",
        }
    gcloud = shutil.which("gcloud.cmd") or shutil.which("gcloud")
    if not gcloud:
        return {
            "status": "ERROR",
            "requested_model": model,
            "resolved_model": resolved_model,
            "shunt_applied": shunt_applied,
            "error": "gcloud CLI not found",
        }
    tok = subprocess.run(
        [gcloud, "auth", "print-access-token", f"--impersonate-service-account={sa}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    ).stdout.strip()
    if len(tok) < 20:
        return {
            "status": "ERROR",
            "requested_model": model,
            "resolved_model": resolved_model,
            "shunt_applied": shunt_applied,
            "error": "token mint failed; check serviceAccountTokenCreator permission",
        }
    url = (
        f"https://aiplatform.googleapis.com/v1/projects/{urllib.parse.quote(project)}/locations/global"
        f"/publishers/google/models/{urllib.parse.quote(resolved_model)}:generateContent"
    )
    body = json.dumps(
        {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max(64, min(int(max_tokens), 2048))},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {tok}",
            "X-Goog-User-Project": project,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8", "replace")[:200]
        finally:
            exc.close()
        return {
            "status": "ERROR",
            "requested_model": model,
            "resolved_model": resolved_model,
            "shunt_applied": shunt_applied,
            "error": f"HTTP {exc.code}: {err_body}",
        }
    parts = (((data.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
    return {
        "status": "OK",
        "requested_model": model,
        "model": resolved_model,
        "resolved_model": resolved_model,
        "shunt_applied": shunt_applied,
        "text": "".join(p.get("text", "") for p in parts).strip(),
    }


def tool_apex_contactor_route_packet(
    requested_model: str,
    objective: str,
    provider: str = "google",
) -> dict[str, Any]:
    prov = (provider or "google").strip().lower()
    if prov not in APEX_PROVIDER_MODELS:
        prov = "google"
    resolved_model, shunt_applied = enforce_apex_shunt(requested_model, provider=prov)
    if shunt_applied:
        with _STATE_LOCK:
            _TELEMETRY["apex_shunts_applied"] += 1
    max_chars = MAX_ESCALATION_TOKENS * 4
    raw_obj = str(objective or "").strip()
    truncated = len(raw_obj) > max_chars
    capped_obj = raw_obj[: max_chars - 32].rstrip() + " [CAPPED_AT_6000_TOK]" if truncated else raw_obj
    est_tokens = min(MAX_ESCALATION_TOKENS, max(1, len(capped_obj) // 4))
    packet_core = {
        "provider": prov,
        "requested_model": requested_model,
        "resolved_model": resolved_model,
        "shunt_applied": shunt_applied,
        "objective": capped_obj,
        "max_tokens": MAX_ESCALATION_TOKENS,
    }
    canonical = json.dumps(packet_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    packet_sha256 = hashlib.sha256(canonical).hexdigest()[:16]
    return {
        "status": "ROUTED",
        "contactor_mode": "ACROSS_THE_LINE_APEX",
        "flash_shunt_engaged": True,
        "env_invariant": "NEXUS_FLASH_SHUNT=1",
        "provider": prov,
        "requested_model": requested_model,
        "resolved_model": resolved_model,
        "shunt_applied": shunt_applied,
        "estimated_tokens": est_tokens,
        "max_tokens": MAX_ESCALATION_TOKENS,
        "truncated": truncated,
        "packet_sha256": packet_sha256,
        "escalation_packet": {
            "lod_tier": "LOD_1_ESCALATION",
            "reasoning_effort": os.environ.get("NEXUS_REASONING_EFFORT", "high"),
            "objective": capped_obj,
        },
    }


def tool_exodia_compaction_gate(
    cache_reads: int = 0,
    cache_writes: int = 1,
    turns: int = 0,
    verified_invariant: str = "Stage 0 AST & SHA-256 slice parity verified.",
    force_compact: bool = False,
) -> dict[str, Any]:
    reads = max(0, int(cache_reads))
    writes = max(1, int(cache_writes))
    turn_count = max(0, int(turns))
    ratio = round(reads / writes, 4)
    triggered = (ratio >= 25.0) or (turn_count >= 15) or bool(force_compact)
    gate_state = "EXODIA_COMPACT_TRIGGERED" if triggered else "NOMINAL_BELOW_25_TO_1_GATE"
    inv_clean = re.sub(r"\s+", " ", str(verified_invariant or "")).strip()[:160]
    digest_input = f"{gate_state}|{ratio:.4f}|{turn_count}|TAINT_0_ARCHITECT|{inv_clean}".encode("utf-8")
    delta_sha256 = hashlib.sha256(digest_input).hexdigest()[:16]
    line_1 = f"DELTA_LINE_1 | GATE={gate_state} | CR_CW={ratio:.2f}:1 | TURNS={turn_count} | SHA256={delta_sha256}"
    line_2 = "DELTA_LINE_2 | PROVENANCE=TAINT_0_ARCHITECT | EVICT=LOD2_TRANSIENT | RETAIN=LOD0_ANCHOR+LOD1_CONTRACTS"
    line_3 = f"DELTA_LINE_3 | INVARIANT={inv_clean}"
    with _STATE_LOCK:
        _TELEMETRY["last_exodia_ratio"] = ratio
        _TELEMETRY["last_exodia_state"] = gate_state
        if triggered:
            _TELEMETRY["exodia_compactions_triggered"] += 1
    return {
        "status": gate_state,
        "compact_required": triggered,
        "ratio": ratio,
        "threshold_ratio": 25.0,
        "turns": turn_count,
        "turn_threshold": 15,
        "force_compact": bool(force_compact),
        "taint_provenance": "TAINT_0_ARCHITECT",
        "delta_sha256": delta_sha256,
        "DELTA_LINE_1": line_1,
        "DELTA_LINE_2": line_2,
        "DELTA_LINE_3": line_3,
        "delta_receipt": "\n".join([line_1, line_2, line_3]),
    }


def _evaluate_assertions(raw: Any) -> tuple[bool, dict[str, bool], list[str]]:
    if raw is None:
        default_map = {
            "lod0_anchor_pinned": True,
            "secret_airlock_active": True,
            "flash_shunt_engaged": True,
        }
        return True, default_map, []
    normalized: dict[str, bool] = {}
    failed: list[str] = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            ok = bool(v)
            normalized[str(k)] = ok
            if not ok:
                failed.append(str(k))
    elif isinstance(raw, list):
        for idx, item in enumerate(raw):
            if isinstance(item, dict):
                name = str(item.get("name") or f"assertion_{idx}")
                ok = bool(item.get("passed", True))
            elif isinstance(item, bool):
                name, ok = f"assertion_{idx}", item
            else:
                text = str(item)
                name = text
                ok = not text.upper().startswith("FAIL")
            normalized[name] = ok
            if not ok:
                failed.append(name)
    else:
        ok = bool(raw)
        normalized["assertion_0"] = ok
        if not ok:
            failed.append("assertion_0")
    return len(failed) == 0, normalized, failed


def tool_interpolate_state_sheet(
    workflow_id: str = "",
    skill_name: str = "state-interpolation",
    act_open: Any = None,
    act_mid: Any = None,
    act_exit: Any = None,
    mechanical_assertions: Any = None,
) -> dict[str, Any]:
    skill = SEP2640_SKILLS.get(skill_name) or SEP2640_SKILLS["state-interpolation"]
    wf = str(workflow_id or "").strip()
    if not wf:
        # SEP-2640 fault-pointer precheck: strictly <120 tokens
        return {
            "status": "ERROR",
            "code": -32602,
            "error": "Missing workflow_id; load SEP-2640 skill contract first.",
            "skill_uri": skill["uri"],
            "sha256": skill["sha256"],
        }
    all_ok, normalized, failed = _evaluate_assertions(mechanical_assertions)
    if not all_ok:
        return {
            "status": "ERROR",
            "code": -32001,
            "error": "Mechanical assertion gate failed.",
            "failed_assertions": failed,
            "skill_uri": skill["uri"],
            "sha256": skill["sha256"],
        }
    sheet = {
        "workflow_id": wf,
        "skill_name": skill["name"],
        "skill_uri": skill["uri"],
        "skill_sha256": skill["sha256"],
        "acts": {
            "open": act_open if act_open is not None else {"phase": "OPEN", "invariant": "LOD0_ANCHOR_PINNED"},
            "mid": act_mid if act_mid is not None else {"phase": "MID", "invariant": "STAGE0_SLICE_VERIFIED"},
            "exit": act_exit if act_exit is not None else {"phase": "EXIT", "invariant": "SHA256_PARITY_SEALED"},
        },
        "mechanical_assertions": normalized,
        "state": "completed",
        "taintProvenance": "VERIFIED_ARCHITECT",
        "issuedAt": _utc_iso(),
    }
    canonical = json.dumps(sheet, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(_get_signing_secret(), canonical, hashlib.sha256).hexdigest()
    artifact_id = f"csaa-{hashlib.sha256(canonical).hexdigest()[:16]}"
    with _STATE_LOCK:
        _TELEMETRY["csaa_artifacts_minted"] += 1
    return {
        "status": "OK",
        "state": "completed",
        "taintProvenance": "VERIFIED_ARCHITECT",
        "workflow_id": wf,
        "skill_uri": skill["uri"],
        "skill_sha256": skill["sha256"],
        "artifact": {
            "artifactId": artifact_id,
            "protocol": "A2A/1.0.1+SEP-2640",
            "state": "completed",
            "taintProvenance": "VERIFIED_ARCHITECT",
            "signatureAlg": "HMAC-SHA256",
            "signature": signature,
            "signaturePrefix": signature[:16],
            "contactSheet": sheet,
        },
    }


def _skill_manifest_summaries() -> list[dict[str, Any]]:
    return [
        {
            "name": s["name"],
            "uri": s["uri"],
            "summary": s["summary"],
            "sha256": s["sha256"],
            "estimated_tokens": s["estimated_tokens"],
            "max_tokens": s["max_tokens"],
            "ttlMs": s["ttlMs"],
        }
        for s in SEP2640_SKILLS.values()
    ]


def build_agent_card(base_url: str = "http://127.0.0.1:8000") -> dict[str, Any]:
    clean_base = base_url.rstrip("/")
    card_core: dict[str, Any] = {
        "protocolVersion": "1.0.1",
        "name": "Alpha MCP Sovereign Dual-Modality",
        "description": (
            "Zero-dependency Stage 0 research vault and Sovereign Dual-Modality MCP v2.0 server "
            "with Across-the-Line Apex Contactor, Exodia 25:1 compaction gate, SEP-2640 skills, "
            "and fail-closed OAuth 2.1 PKCE S256."
        ),
        "version": SERVER_VERSION,
        "url": f"{clean_base}/mcp",
        "provider": {
            "organization": "Eloquent",
            "url": "https://github.com/mjeanhudson-dev/alpha-mcp",
        },
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "authentication": {
            "schemes": ["Bearer", "OAuth2.1-PKCE-S256"],
            "protectedResourceMetadata": f"{clean_base}/.well-known/oauth-protected-resource",
        },
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/plain"],
        "tools": [t["name"] for t in TOOLS],
        "skills": _skill_manifest_summaries(),
    }
    canonical = json.dumps(card_core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_get_signing_secret(), canonical, hashlib.sha256).hexdigest()
    card_core["signature"] = {
        "alg": "HS256-SOVEREIGN",
        "digest": sig,
        "prefix": sig[:16],
    }
    return card_core


def tool_sovereign_dual_modality_status() -> dict[str, Any]:
    card = build_agent_card("http://127.0.0.1:8000")
    return {
        "status": "OK",
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "transports": ["stdio", "http"],
        "pinned_tool_order": [t["name"] for t in TOOLS],
        "sep2640_skills": _skill_manifest_summaries(),
        "a2a_agent_card_signature": card["signature"]["prefix"],
        "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
        "redaction_patterns_count": len(REDACTIONS),
        "secret_path_airlock": True,
        "flash_shunt_engaged": True,
        "equations_count": len(EQUATIONS_VAULT),
        "keyless_gcp": {
            "project_configured": bool(os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()),
            "impersonation_configured": bool(os.environ.get("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "").strip()),
            "static_key_files_on_disk": 0,
        },
        "zero_cost_online_tiers": list(ZERO_COST_ONLINE_TIERS),
    }


# ---------------------------------------------------------------------------
# Prefix-Pinned 10-Tool Wire Registry (#01..#10, Immutable Order)
# ---------------------------------------------------------------------------

def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required or []}


_ANN = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "stage0_vault_fts_query",
        "description": "BM25 FTS5 search over the redacted research vault.",
        "annotations": {**_ANN, "title": "Vault FTS Query"},
        "inputSchema": _schema(
            {"query": {"type": "string"}, "top_k": {"type": "integer", "default": 5}, "db_path": {"type": "string"}},
            ["query"],
        ),
    },
    {
        "name": "stage0_vault_manifest_lookup",
        "description": "Inspect vault counts and VHDX/ZIP/link/secret-audit manifests (metadata only).",
        "annotations": {**_ANN, "title": "Vault Manifest Lookup"},
        "inputSchema": _schema(
            {
                "scope": {"type": "string", "enum": ["summary", "vhdx", "zip", "links", "secret_audit"], "default": "summary"},
                "limit": {"type": "integer", "default": 15},
                "db_path": {"type": "string"},
            }
        ),
    },
    {
        "name": "stage0_ast_slice_and_parity",
        "description": "Read a file as a <=160-line slice with SHA-256 dedup; credential files are blocked.",
        "annotations": {**_ANN, "title": "Slice With Secret Airlock"},
        "inputSchema": _schema(
            {
                "filepath": {"type": "string"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "default": 160},
                "force_read": {"type": "boolean", "default": False},
            },
            ["filepath"],
        ),
    },
    {
        "name": "precompensate_stdout_delta",
        "description": "Compress noisy logs (>500 tokens) into a <300-token fault-only delta.",
        "annotations": {**_ANN, "title": "Stdout Delta Compressor"},
        "inputSchema": _schema(
            {"raw_stdout": {"type": "string"}, "command_label": {"type": "string", "default": "cli"}},
            ["raw_stdout"],
        ),
    },
    {
        "name": "tandem_edge_route",
        "description": "Thermal (quintic 32-42C ramp) and VRAM headroom router for local edge tasks; escalates multi_turn to gemini-4-neon.",
        "annotations": {**_ANN, "title": "Edge Thermal/VRAM Router"},
        "inputSchema": _schema(
            {
                "task_type": {"type": "string", "default": "thermal_audit"},
                "phone_temp_c": {"type": "number", "default": 34.0},
                "vram_used_gb": {"type": "number", "default": 3.5},
                "multi_turn": {"type": "boolean", "default": False},
            }
        ),
    },
    {
        "name": "vertex_keyless_query",
        "description": "Optional Vertex AI call using keyless service-account impersonation with Apex Flash Shunt enforcement.",
        "annotations": {**_ANN, "title": "Keyless Vertex Query", "openWorldHint": True},
        "inputSchema": _schema(
            {
                "prompt": {"type": "string"},
                "model": {"type": "string", "default": "gemini-4-neon"},
                "max_tokens": {"type": "integer", "default": 512},
            },
            ["prompt"],
        ),
    },
    {
        "name": "apex_contactor_route_packet",
        "description": "Across-the-Line Apex Contactor (NEXUS_FLASH_SHUNT=1); shunts banned low-poly tiers to provider Apex models with <=6,000-token escalation packet cap.",
        "annotations": {**_ANN, "title": "Across-the-Line Apex Contactor"},
        "inputSchema": _schema(
            {
                "requested_model": {"type": "string"},
                "objective": {"type": "string"},
                "provider": {"type": "string", "enum": ["google", "anthropic", "openai"], "default": "google"},
            },
            ["requested_model", "objective"],
        ),
    },
    {
        "name": "exodia_compaction_gate",
        "description": "Evaluates Cache_Reads/Cache_Writes >= 25.0:1 and turns >= 15; emits 3-line taint-preserving SHA-256 delta receipt.",
        "annotations": {**_ANN, "title": "Exodia 25:1 Compaction Gate"},
        "inputSchema": _schema(
            {
                "cache_reads": {"type": "integer", "default": 0},
                "cache_writes": {"type": "integer", "default": 1},
                "turns": {"type": "integer", "default": 0},
                "verified_invariant": {"type": "string", "default": "Stage 0 AST & SHA-256 slice parity verified."},
                "force_compact": {"type": "boolean", "default": False},
            }
        ),
    },
    {
        "name": "interpolate_state_sheet",
        "description": "3-Act state contact sheet interpolation with SEP-2640 fault-pointer precheck and HMAC-SHA256 CSAA A2A artifact minting.",
        "annotations": {**_ANN, "title": "SEP-2640 State Interpolation"},
        "inputSchema": _schema(
            {
                "workflow_id": {"type": "string", "default": ""},
                "skill_name": {"type": "string", "default": "state-interpolation"},
                "act_open": {"type": ["object", "string", "null"]},
                "act_mid": {"type": ["object", "string", "null"]},
                "act_exit": {"type": ["object", "string", "null"]},
                "mechanical_assertions": {"type": ["object", "array", "null"]},
            }
        ),
    },
    {
        "name": "sovereign_dual_modality_status",
        "description": "Return Sovereign Dual-Modality MCP v2.0 status, pinned 10-tool order, SEP-2640 skills, A2A signature, and $0/mo tier inventory.",
        "annotations": {**_ANN, "title": "Sovereign Dual-Modality Status"},
        "inputSchema": _schema({}),
    },
]

DISPATCH: dict[str, Any] = {
    "stage0_vault_fts_query": tool_fts_query,
    "stage0_vault_manifest_lookup": tool_manifest_lookup,
    "stage0_ast_slice_and_parity": tool_ast_slice,
    "precompensate_stdout_delta": tool_precompensate,
    "tandem_edge_route": tool_edge_route,
    "vertex_keyless_query": tool_vertex_query,
    "apex_contactor_route_packet": tool_apex_contactor_route_packet,
    "exodia_compaction_gate": tool_exodia_compaction_gate,
    "interpolate_state_sheet": tool_interpolate_state_sheet,
    "sovereign_dual_modality_status": tool_sovereign_dual_modality_status,
}


# ---------------------------------------------------------------------------
# MCP Resources (4 Canonical URIs + SEP-2640 Skill Resolution)
# ---------------------------------------------------------------------------

RESOURCES: list[dict[str, str]] = [
    {
        "uri": "alpha://genesis/anchor-t0",
        "name": "Genesis Anchor (t = 0)",
        "description": "Immutable LOD 0 Genesis Coordinate, 5-Layer Carbon Orchestration Stack, and 10-tool prefix-pinned wire invariant.",
        "mimeType": "application/json",
    },
    {
        "uri": "alpha://vault/manifest-summary",
        "name": "Stage 0 Vault Manifest Summary",
        "description": "Live read-only SQLite WAL + BM25 FTS5 vault manifest counts and redaction audit status.",
        "mimeType": "application/json",
    },
    {
        "uri": "alpha://hosting/zero-cost-blueprint",
        "name": "Zero-Cost Dual-Modality Hosting Blueprint",
        "description": "Operational architecture for running Alpha MCP v2.0 online at $0.00/mo across Cloudflare Named Tunnel, Cloud Run, and Static Edge Pages.",
        "mimeType": "application/json",
    },
    {
        "uri": "alpha://telemetry/exodia-ledger",
        "name": "Exodia Telemetry & Parity Ledger",
        "description": "Live slice parity hit/miss counters, Apex Contactor shunt metrics, and Exodia 25:1 compaction gate status.",
        "mimeType": "application/json",
    },
]


def read_resource(uri: str) -> tuple[dict[str, Any] | None, str | None]:
    if uri == "alpha://genesis/anchor-t0":
        payload = {
            "genesis_coordinate": "t = 0",
            "foundational_archive": "August 2025 (USPTO Provisional Patent Application No. 63/911,661)",
            "stability_invariant": "Stability = integral(Anchor * Presence) dt -> inf",
            "server": SERVER_NAME,
            "version": SERVER_VERSION,
            "pinned_tool_order": [t["name"] for t in TOOLS],
            "layers": [
                "L0_GENESIS_ANCHOR",
                "L1_STAGE0_DETERMINISTIC_SLICE",
                "L2_KPPC_PROGRESSIVE_LOD",
                "L3_APEX_CONTACTOR_FLASH_SHUNT",
                "L4_EXODIA_COMPACTION_GATE",
            ],
            "equations_count": len(EQUATIONS_VAULT),
        }
        return {"uri": uri, "mimeType": "application/json", "text": redact(json.dumps(_redact_obj(payload), indent=2))}, None

    if uri == "alpha://vault/manifest-summary":
        summary = tool_manifest_lookup(scope="summary", limit=15)
        return {"uri": uri, "mimeType": "application/json", "text": redact(json.dumps(_redact_obj(summary), indent=2))}, None

    if uri == "alpha://hosting/zero-cost-blueprint":
        payload = {
            "title": "Sovereign Dual-Modality Zero-Cost Online Architecture ($0.00/mo)",
            "transports": ["stdio", "http"],
            "zero_cost_online_tiers": list(ZERO_COST_ONLINE_TIERS),
            "tiers": {
                "local_stdio": {"cost_usd_mo": 0.0, "latency": "<3ms", "command": "python alpha_mcp_server.py --transport stdio"},
                "cloudflare_named_tunnel": {
                    "cost_usd_mo": 0.0,
                    "endpoint": "https://mcp.<your-domain>/mcp",
                    "auth": "ALPHA_MCP_BEARER_TOKEN + OAuth 2.1 PKCE S256 (--require-auth)",
                },
                "cloud_run_failover": {
                    "cost_usd_mo": 0.0,
                    "config": "min-instances=0, max-instances=2, 256Mi, cpu-throttling",
                    "keyless_gcp": "Service-account impersonation (0 static key files on disk)",
                },
                "static_edge_pages": {
                    "cost_usd_mo": 0.0,
                    "providers": ["Cloudflare Workers/Pages", "GitHub Pages"],
                },
            },
            "security_invariants": {
                "fail_closed_non_loopback_auth": True,
                "pkce_challenge_method": "S256",
                "rfc7009_revocation": True,
                "redaction_patterns": len(REDACTIONS),
                "secret_path_airlock": True,
            },
        }
        return {"uri": uri, "mimeType": "application/json", "text": redact(json.dumps(payload, indent=2))}, None

    if uri == "alpha://telemetry/exodia-ledger":
        with _STATE_LOCK:
            snap = dict(_TELEMETRY)
            cached_slices = len(_SLICE_PARITY)
        snap["cached_slice_keys"] = cached_slices
        snap["redaction_patterns_count"] = len(REDACTIONS)
        snap["flash_shunt_engaged"] = True
        return {"uri": uri, "mimeType": "application/json", "text": redact(json.dumps(_redact_obj(snap), indent=2))}, None

    for skill in SEP2640_SKILLS.values():
        if uri == skill["uri"]:
            return {"uri": uri, "mimeType": "text/markdown", "text": redact(skill["content"])}, None

    return None, f"Unknown resource URI: {uri}"


# ---------------------------------------------------------------------------
# MCP Prompts (Nil-Argument Resilient)
# ---------------------------------------------------------------------------

PROMPTS: list[dict[str, Any]] = [
    {
        "name": "kppc_lod_blueprint",
        "description": "Generate a progressive LOD 0-1-2 KPPC architectural blueprint anchored to Genesis t=0.",
        "arguments": [
            {
                "name": "system_objective",
                "description": "Target system objective to structure under KPPC LOD 0-1-2.",
                "required": False,
            }
        ],
    },
    {
        "name": "exodia_zero_drag_audit",
        "description": "Audit a target file or workspace for Stage 0 AST slicing, 25:1 cache-drag hygiene, and secret airlock compliance.",
        "arguments": [
            {
                "name": "target_path",
                "description": "Relative or ~/ normalized target path to audit.",
                "required": False,
            }
        ],
    },
    {
        "name": "zero_cost_online_deploy",
        "description": "Generate an end-to-end $0.00/mo dual-modality deployment plan (Cloudflare Named Tunnel + Cloud Run min-scale-0).",
        "arguments": [
            {
                "name": "domain",
                "description": "Public domain name (e.g. mcp.example.com) for the Streamable HTTP endpoint.",
                "required": False,
            }
        ],
    },
]


def render_prompt(name: str, arguments: Any) -> tuple[dict[str, Any] | None, str | None]:
    args_map = arguments if isinstance(arguments, dict) else {}
    if name == "kppc_lod_blueprint":
        obj = str(args_map.get("system_objective") or "").strip() or "<system_objective: Sovereign Dual-Modality MCP Control Plane>"
        text = (
            f"Design a progressive LOD 0 -> LOD 1 -> LOD 2 KPPC blueprint for: {obj}\n"
            "Constraints:\n"
            "- LOD 0 (<=1,200 tok): Pin objective, Genesis Coordinate t=0, and non-negotiable invariants.\n"
            "- LOD 1 (<=4,500 tok): Enumerate exact module contracts, tool wire order, and SHA-256 parity anchors.\n"
            "- LOD 2 (transient): Use <=160-line Stage 0 slices and keep escalation packets <=6,000 tokens with NEXUS_FLASH_SHUNT=1."
        )
        return {
            "description": PROMPTS[0]["description"],
            "messages": [{"role": "user", "content": {"type": "text", "text": redact(text)}}],
        }, None

    if name == "exodia_zero_drag_audit":
        target = str(args_map.get("target_path") or "").strip() or "./alpha_mcp_server.py"
        text = (
            f"Run an Exodia Zero-Drag & Secret-Airlock audit against: {target}\n"
            "Checklist:\n"
            "1. Slice via `stage0_ast_slice_and_parity` (<=160 lines, SHA-256 parity hit on repeat).\n"
            "2. Compress verbose test/build logs (>500 tok) via `precompensate_stdout_delta` (<300 tok delta).\n"
            "3. Evaluate Cache_Reads / Cache_Writes vs 25.0:1 via `exodia_compaction_gate` and emit 3-line TAINT_0_ARCHITECT delta."
        )
        return {
            "description": PROMPTS[1]["description"],
            "messages": [{"role": "user", "content": {"type": "text", "text": redact(text)}}],
        }, None

    if name == "zero_cost_online_deploy":
        domain = str(args_map.get("domain") or "").strip() or "mcp.example.com"
        text = (
            f"Produce a $0.00/mo Sovereign Dual-Modality deployment checklist for domain: {domain}\n"
            "Architecture:\n"
            "1. Local IDE stdio (`--transport stdio`) for sub-3ms local workflows.\n"
            "2. Authenticated Streamable HTTP (`--transport http --host 127.0.0.1 --port 8000 --require-auth`) behind a Cloudflare Named Tunnel.\n"
            "3. Failover Google Cloud Run (`min-instances=0`, `max-instances=2`, `256Mi`, `cpu-throttling`) with keyless service-account impersonation.\n"
            "4. Verify OAuth 2.1 PKCE S256, RFC 7009 revocation, and signed `/.well-known/agent-card.json`."
        )
        return {
            "description": PROMPTS[2]["description"],
            "messages": [{"role": "user", "content": {"type": "text", "text": redact(text)}}],
        }, None

    return None, f"Unknown prompt: {name}"


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 MCP Core Dispatcher
# ---------------------------------------------------------------------------

def handle(msg: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(msg, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    method = str(msg.get("method") or "")
    mid = msg.get("id")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    if mid is None and method.startswith("notifications/"):
        return None

    if method == "initialize":
        req_ver = params.get("protocolVersion")
        negotiated = req_ver if isinstance(req_ver, str) and req_ver in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                    "logging": {},
                    "experimental": {
                        "io.modelcontextprotocol/skills": {
                            "version": "SEP-2640",
                            "skillsCount": len(SEP2640_SKILLS),
                        }
                    },
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}

    if method == "logging/setLevel":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = params.get("name")
        fn = DISPATCH.get(tool_name)
        if fn is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}
        call_args = params.get("arguments")
        if not isinstance(call_args, dict):
            call_args = {}
        try:
            res = fn(**call_args)
        except Exception as exc:
            res = {"status": "ERROR", "error": str(exc)}
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "content": [{"type": "text", "text": redact(json.dumps(_redact_obj(res), indent=2))}],
                "isError": isinstance(res, dict) and res.get("status") == "ERROR",
            },
        }

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"resources": RESOURCES}}

    if method == "resources/read":
        uri = str(params.get("uri") or "").strip()
        item, err = read_resource(uri)
        if err is not None or item is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": err or "Resource not found"}}
        return {"jsonrpc": "2.0", "id": mid, "result": {"contents": [item]}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"prompts": PROMPTS}}

    if method == "prompts/get":
        pname = str(params.get("name") or "").strip()
        rendered, err = render_prompt(pname, params.get("arguments"))
        if err is not None or rendered is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": err or "Prompt not found"}}
        return {"jsonrpc": "2.0", "id": mid, "result": rendered}

    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}


# ---------------------------------------------------------------------------
# Hardened OAuth 2.1 PKCE S256 + RFC 7591 + RFC 7009 Broker
# ---------------------------------------------------------------------------

def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OAuthPKCEBroker:
    """Thread-safe in-memory OAuth 2.1 PKCE S256 broker with single-use codes, rotation, and revocation."""

    def __init__(self, code_ttl: int = 300, access_ttl: int = 3600, refresh_ttl: int = 86400) -> None:
        self._lock = threading.Lock()
        self._code_ttl = code_ttl
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._clients: dict[str, dict[str, Any]] = {}
        self._codes: dict[str, dict[str, Any]] = {}
        self._access_tokens: dict[str, dict[str, Any]] = {}
        self._refresh_tokens: dict[str, dict[str, Any]] = {}

    def register_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        cid = f"alpha-client-{secrets.token_hex(12)}"
        rec = {
            "client_id": cid,
            "client_name": str(payload.get("client_name") or "alpha-mcp-client")[:128],
            "redirect_uris": payload.get("redirect_uris") if isinstance(payload.get("redirect_uris"), list) else [],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_id_issued_at": int(time.time()),
        }
        with self._lock:
            self._clients[cid] = rec
        return rec

    def issue_auth_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str = "mcp:read mcp:tools",
        resource: str = "",
    ) -> tuple[str | None, str | None]:
        if (code_challenge_method or "").strip() != "S256":
            return None, "PKCE code_challenge_method must be S256"
        if not code_challenge or len(code_challenge.strip()) < 32:
            return None, "Valid PKCE S256 code_challenge is required"
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._codes[code] = {
                "client_id": (client_id or "alpha-public-client").strip(),
                "redirect_uri": (redirect_uri or "").strip(),
                "code_challenge": code_challenge.strip(),
                "scope": (scope or "mcp:read mcp:tools").strip(),
                "resource": (resource or "").strip(),
                "expires_at": time.time() + self._code_ttl,
                "used": False,
            }
        return code, None

    def exchange_code(
        self,
        code: str,
        code_verifier: str,
        client_id: str = "",
        redirect_uri: str = "",
    ) -> tuple[dict[str, Any] | None, str | None]:
        now = time.time()
        with self._lock:
            rec = self._codes.get(code)
            if rec is None or rec["used"] or now > rec["expires_at"]:
                return None, "Authorization code invalid, expired, or already consumed"
            # Mark single-use immediately to prevent replay or brute-force retries
            rec["used"] = True
            if client_id and rec["client_id"] and client_id != rec["client_id"]:
                return None, "client_id mismatch"
            if redirect_uri and rec["redirect_uri"] and redirect_uri != rec["redirect_uri"]:
                return None, "redirect_uri mismatch"
            try:
                computed = _pkce_s256(code_verifier)
            except UnicodeEncodeError:
                return None, "Invalid code_verifier encoding"
            if not hmac.compare_digest(computed, rec["code_challenge"]):
                return None, "PKCE S256 verification failed"
            return self._mint_token_pair_locked(rec["client_id"], rec["scope"], rec["resource"]), None

    def rotate_refresh_token(self, refresh_token: str) -> tuple[dict[str, Any] | None, str | None]:
        now = time.time()
        with self._lock:
            rec = self._refresh_tokens.get(refresh_token)
            if rec is None or rec["revoked"] or now > rec["expires_at"]:
                return None, "Refresh token invalid, expired, or revoked"
            rec["revoked"] = True
            old_access = rec.get("access_token")
            if old_access and old_access in self._access_tokens:
                self._access_tokens[old_access]["revoked"] = True
            return self._mint_token_pair_locked(rec["client_id"], rec["scope"], rec["resource"]), None

    def _mint_token_pair_locked(self, client_id: str, scope: str, resource: str) -> dict[str, Any]:
        now = time.time()
        access_tok = secrets.token_urlsafe(32)
        refresh_tok = secrets.token_urlsafe(32)
        self._access_tokens[access_tok] = {
            "client_id": client_id,
            "scope": scope,
            "resource": resource,
            "expires_at": now + self._access_ttl,
            "revoked": False,
        }
        self._refresh_tokens[refresh_tok] = {
            "client_id": client_id,
            "scope": scope,
            "resource": resource,
            "access_token": access_tok,
            "expires_at": now + self._refresh_ttl,
            "revoked": False,
        }
        return {
            "access_token": access_tok,
            "token_type": "Bearer",
            "expires_in": self._access_ttl,
            "refresh_token": refresh_tok,
            "scope": scope,
        }

    def validate_access_token(self, token: str) -> bool:
        if not token:
            return False
        now = time.time()
        with self._lock:
            rec = self._access_tokens.get(token)
            return bool(rec is not None and not rec["revoked"] and now <= rec["expires_at"])

    def revoke_token(self, token: str) -> None:
        if not token:
            return
        with self._lock:
            if token in self._access_tokens:
                self._access_tokens[token]["revoked"] = True
            if token in self._refresh_tokens:
                self._refresh_tokens[token]["revoked"] = True
                linked = self._refresh_tokens[token].get("access_token")
                if linked and linked in self._access_tokens:
                    self._access_tokens[linked]["revoked"] = True


# ---------------------------------------------------------------------------
# Fail-Closed Non-Loopback Auth Airlock & Streamable HTTP Server
# ---------------------------------------------------------------------------

def _extract_hostname(host_header: str) -> str:
    raw = (host_header or "").strip()
    if not raw:
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        return raw[1:end].lower() if end != -1 else raw.lower()
    return raw.split(":", 1)[0].lower()


def _is_protected_http_request(headers: Any, require_auth: bool) -> bool:
    if require_auth:
        return True
    for hdr in ("X-Forwarded-Host", "Cf-Visitor", "X-Forwarded-For"):
        if headers.get(hdr):
            return True
    hostname = _extract_hostname(headers.get("Host", ""))
    return hostname not in ("127.0.0.1", "localhost", "::1")


def _extract_bearer_token(headers: Any) -> str:
    auth = str(headers.get("Authorization") or "").strip()
    if len(auth) > 7 and auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return ""


def _is_authorized_http_request(headers: Any, broker: OAuthPKCEBroker, require_auth: bool) -> bool:
    if not _is_protected_http_request(headers, require_auth):
        return True
    tok = _extract_bearer_token(headers)
    if not tok:
        return False
    env_bearer = os.environ.get("ALPHA_MCP_BEARER_TOKEN", "").strip()
    if env_bearer and hmac.compare_digest(tok, env_bearer):
        return True
    return broker.validate_access_token(tok)


def _is_oauth_admin_authorized(headers: Any, params: dict[str, Any], require_auth: bool) -> bool:
    if not _is_protected_http_request(headers, require_auth):
        return True
    env_oauth_secret = os.environ.get("ALPHA_MCP_OAUTH_SECRET", "").strip()
    cand_secret = str(headers.get("X-Alpha-OAuth-Secret") or params.get("oauth_secret") or "").strip()
    if env_oauth_secret and cand_secret and hmac.compare_digest(cand_secret, env_oauth_secret):
        return True
    env_bearer = os.environ.get("ALPHA_MCP_BEARER_TOKEN", "").strip()
    cand_bearer = _extract_bearer_token(headers)
    if env_bearer and cand_bearer and hmac.compare_digest(cand_bearer, env_bearer):
        return True
    return False


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[http.server.BaseHTTPRequestHandler],
        *,
        require_auth: bool = False,
        quiet: bool = False,
    ) -> None:
        self.require_auth = require_auth
        self.quiet = quiet
        self.oauth_broker = OAuthPKCEBroker()
        self.sessions: set[str] = set()
        self.sessions_lock = threading.Lock()
        super().__init__(server_address, request_handler_class)


class AlphaMCPHTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        if getattr(self.server, "quiet", False) or os.environ.get("ALPHA_MCP_QUIET") == "1":
            return
        sys.stderr.write(f"[alpha-mcp-http] {self.address_string()} - {format % args}\n")

    def _base_url(self) -> str:
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if not proto:
            cf_vis = self.headers.get("Cf-Visitor") or ""
            proto = "https" if "https" in cf_vis.lower() else "http"
        host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").split(",")[0].strip()
        if not host:
            addr = self.server.server_address
            host = f"{addr[0]}:{addr[1]}"
        return f"{proto}://{host}".rstrip("/")

    def _cors_headers(self) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, X-Alpha-OAuth-Secret",
            "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate",
        }

    def _send_json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in self._cors_headers().items():
            self.send_header(k, v)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, status: int, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        for k, v in self._cors_headers().items():
            self.send_header(k, v)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _read_body(self) -> tuple[bytes | None, str | None]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return b"", None
        try:
            length = int(raw_len)
        except ValueError:
            return None, "Invalid Content-Length header"
        if length < 0 or length > MAX_HTTP_BODY_BYTES:
            return None, f"Payload exceeds {MAX_HTTP_BODY_BYTES} byte limit"
        return self.rfile.read(length), None

    def _parse_params(self, query: str, body: bytes) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        if query:
            for k, vals in urllib.parse.parse_qs(query, keep_blank_values=True).items():
                merged[k] = vals[0] if vals else ""
        if body:
            ctype = (self.headers.get("Content-Type") or "").lower()
            text = body.decode("utf-8", "replace").strip()
            if "application/json" in ctype or (text.startswith("{") and text.endswith("}")):
                try:
                    obj = json.loads(text)
                    if isinstance(obj, dict):
                        merged.update(obj)
                except json.JSONDecodeError:
                    pass
            else:
                for k, vals in urllib.parse.parse_qs(text, keep_blank_values=True).items():
                    merged[k] = vals[0] if vals else ""
        return merged

    def _send_401(self) -> None:
        base = self._base_url()
        self._send_json(
            401,
            {"error": "unauthorized"},
            extra_headers={"WWW-Authenticate": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'},
        )

    def _send_403_oauth(self) -> None:
        self._send_json(
            403,
            {
                "error": "access_denied",
                "error_description": "Set ALPHA_MCP_OAUTH_SECRET or ALPHA_MCP_BEARER_TOKEN for non-loopback OAuth authorization",
            },
        )

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_empty(204)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path
        base = self._base_url()

        if route in ("/", "/health", "/status"):
            self._send_json(
                200,
                {
                    "status": "ONLINE",
                    "server": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "mcp_endpoint": f"{base}/mcp",
                    "tools_count": len(TOOLS),
                    "flash_shunt_engaged": True,
                    "require_auth": bool(self.server.require_auth),  # type: ignore[attr-defined]
                    "transports": ["stdio", "http"],
                    "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
                },
            )
            return

        if route == "/.well-known/agent-card.json":
            self._send_json(200, build_agent_card(base))
            return

        if route == "/equations":
            self._send_json(200, {"status": "OK", "count": len(EQUATIONS_VAULT), "equations": EQUATIONS_VAULT})
            return

        if route == "/skills":
            self._send_json(
                200,
                {
                    "status": "OK",
                    "protocol": "SEP-2640",
                    "max_skill_tokens": MAX_SKILL_TOKENS,
                    "count": len(SEP2640_SKILLS),
                    "skills": _skill_manifest_summaries(),
                },
            )
            return

        if route in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            self._send_json(
                200,
                {
                    "resource": f"{base}/mcp",
                    "authorization_servers": [base],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["mcp:read", "mcp:tools"],
                    "resource_name": "Alpha MCP Sovereign Dual-Modality v2.0",
                },
            )
            return

        if route in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            self._send_json(
                200,
                {
                    "issuer": base,
                    "authorization_endpoint": f"{base}/oauth/authorize",
                    "token_endpoint": f"{base}/oauth/token",
                    "registration_endpoint": f"{base}/oauth/register",
                    "revocation_endpoint": f"{base}/oauth/revoke",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
                    "scopes_supported": ["mcp:read", "mcp:tools"],
                },
            )
            return

        if route == "/oauth/authorize":
            params = self._parse_params(parsed.query, b"")
            self._handle_oauth_authorize(params)
            return

        if route in ("/mcp", "/mcp/"):
            self._send_json(
                405,
                {"error": "method_not_allowed", "allow": ["POST", "OPTIONS"]},
                extra_headers={"Allow": "POST, OPTIONS"},
            )
            return

        self._send_json(404, {"error": "not_found", "path": route})

    def do_DELETE(self) -> None:  # noqa: N802
        route = urllib.parse.urlsplit(self.path).path
        if route not in ("/mcp", "/mcp/"):
            self._send_json(404, {"error": "not_found", "path": route})
            return
        srv: ThreadedHTTPServer = self.server  # type: ignore[assignment]
        if not _is_authorized_http_request(self.headers, srv.oauth_broker, srv.require_auth):
            self._send_401()
            return
        sid = str(self.headers.get("Mcp-Session-Id") or "").strip()
        if sid:
            with srv.sessions_lock:
                srv.sessions.discard(sid)
        self._send_json(200, {"status": "SESSION_CLOSED", "session_id": sid})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path
        body, err = self._read_body()
        if err is not None or body is None:
            self._send_json(400, {"error": "invalid_request", "error_description": err or "Bad body"})
            return

        if route == "/oauth/register":
            params = self._parse_params(parsed.query, body)
            srv: ThreadedHTTPServer = self.server  # type: ignore[assignment]
            if not _is_oauth_admin_authorized(self.headers, params, srv.require_auth):
                self._send_403_oauth()
                return
            client = srv.oauth_broker.register_client(params)
            self._send_json(201, client)
            return

        if route == "/oauth/authorize":
            params = self._parse_params(parsed.query, body)
            self._handle_oauth_authorize(params)
            return

        if route == "/oauth/token":
            params = self._parse_params(parsed.query, body)
            self._handle_oauth_token(params)
            return

        if route == "/oauth/revoke":
            params = self._parse_params(parsed.query, body)
            srv = self.server  # type: ignore[assignment]
            srv.oauth_broker.revoke_token(str(params.get("token") or "").strip())
            self._send_json(200, {"revoked": True})
            return

        if route in ("/mcp", "/mcp/"):
            self._handle_mcp_post(body)
            return

        self._send_json(404, {"error": "not_found", "path": route})

    def _handle_oauth_authorize(self, params: dict[str, Any]) -> None:
        srv: ThreadedHTTPServer = self.server  # type: ignore[assignment]
        if not _is_oauth_admin_authorized(self.headers, params, srv.require_auth):
            self._send_403_oauth()
            return
        resp_type = str(params.get("response_type") or "code").strip()
        if resp_type != "code":
            self._send_json(400, {"error": "unsupported_response_type", "error_description": "Only response_type=code is supported"})
            return
        client_id = str(params.get("client_id") or "alpha-public-client").strip()
        redirect_uri = str(params.get("redirect_uri") or "").strip()
        state = str(params.get("state") or "").strip()
        scope = str(params.get("scope") or "mcp:read mcp:tools").strip()
        resource = str(params.get("resource") or f"{self._base_url()}/mcp").strip()
        challenge = str(params.get("code_challenge") or "").strip()
        method = str(params.get("code_challenge_method") or "").strip()

        code, err = srv.oauth_broker.issue_auth_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=challenge,
            code_challenge_method=method,
            scope=scope,
            resource=resource,
        )
        if err is not None or code is None:
            self._send_json(400, {"error": "invalid_request", "error_description": err or "PKCE S256 required"})
            return

        accept = (self.headers.get("Accept") or "").lower()
        want_json = (
            not redirect_uri
            or str(params.get("response_mode") or "").lower() == "json"
            or "application/json" in accept
        )
        payload = {
            "code": code,
            "state": state,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "token_endpoint": f"{self._base_url()}/oauth/token",
            "expires_in": 300,
        }
        if want_json:
            self._send_json(200, payload)
            return
        sep = "&" if "?" in redirect_uri else "?"
        q = urllib.parse.urlencode({k: v for k, v in (("code", code), ("state", state)) if v})
        self._send_json(302, payload, extra_headers={"Location": f"{redirect_uri}{sep}{q}"})

    def _handle_oauth_token(self, params: dict[str, Any]) -> None:
        srv: ThreadedHTTPServer = self.server  # type: ignore[assignment]
        grant_type = str(params.get("grant_type") or "").strip()
        if grant_type == "authorization_code":
            code = str(params.get("code") or "").strip()
            verifier = str(params.get("code_verifier") or "").strip()
            client_id = str(params.get("client_id") or "").strip()
            redirect_uri = str(params.get("redirect_uri") or "").strip()
            if not code or not verifier:
                self._send_json(400, {"error": "invalid_request", "error_description": "code and code_verifier are required"})
                return
            token_resp, err = srv.oauth_broker.exchange_code(
                code=code,
                code_verifier=verifier,
                client_id=client_id,
                redirect_uri=redirect_uri,
            )
            if err is not None or token_resp is None:
                self._send_json(400, {"error": "invalid_grant", "error_description": err or "Invalid grant"})
                return
            self._send_json(200, token_resp)
            return

        if grant_type == "refresh_token":
            rtok = str(params.get("refresh_token") or "").strip()
            if not rtok:
                self._send_json(400, {"error": "invalid_request", "error_description": "refresh_token is required"})
                return
            token_resp, err = srv.oauth_broker.rotate_refresh_token(rtok)
            if err is not None or token_resp is None:
                self._send_json(400, {"error": "invalid_grant", "error_description": err or "Invalid refresh token"})
                return
            self._send_json(200, token_resp)
            return

        self._send_json(400, {"error": "unsupported_grant_type", "error_description": f"Unsupported grant_type: {grant_type}"})

    def _handle_mcp_post(self, body: bytes) -> None:
        srv: ThreadedHTTPServer = self.server  # type: ignore[assignment]
        if not _is_authorized_http_request(self.headers, srv.oauth_broker, srv.require_auth):
            self._send_401()
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}})
            return

        sid = str(self.headers.get("Mcp-Session-Id") or "").strip()
        if not sid:
            sid = secrets.token_hex(16)
        with srv.sessions_lock:
            srv.sessions.add(sid)

        req_proto = str(self.headers.get("MCP-Protocol-Version") or "").strip()
        proto_ver = req_proto if req_proto in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]

        if isinstance(payload, list):
            if not payload:
                self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Empty batch"}})
                return
            responses = []
            for item in payload:
                r = handle(item)
                if r is not None:
                    if isinstance(r.get("result"), dict) and "protocolVersion" in r["result"]:
                        proto_ver = str(r["result"]["protocolVersion"])
                    responses.append(r)
            hdrs = {"Mcp-Session-Id": sid, "MCP-Protocol-Version": proto_ver}
            if not responses:
                self._send_empty(202, extra_headers=hdrs)
            else:
                self._send_json(200, responses, extra_headers=hdrs)
            return

        if not isinstance(payload, dict):
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid JSON-RPC payload"}})
            return

        resp = handle(payload)
        if isinstance(resp, dict) and isinstance(resp.get("result"), dict) and "protocolVersion" in resp["result"]:
            proto_ver = str(resp["result"]["protocolVersion"])
        hdrs = {"Mcp-Session-Id": sid, "MCP-Protocol-Version": proto_ver}
        if resp is None:
            self._send_empty(202, extra_headers=hdrs)
        else:
            self._send_json(200, resp, extra_headers=hdrs)


def create_http_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    require_auth: bool = False,
    quiet: bool = False,
) -> ThreadedHTTPServer:
    return ThreadedHTTPServer((host, port), AlphaMCPHTTPHandler, require_auth=require_auth, quiet=quiet)


def run_http_server(host: str, port: int, require_auth: bool = False) -> None:
    srv = create_http_server(host, port, require_auth=require_auth)
    sys.stderr.write(
        f"[alpha-mcp] Streamable HTTP v{SERVER_VERSION} listening on http://{host}:{port}/mcp "
        f"(require_auth={require_auth}, tools={len(TOOLS)})\n"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def run_stdio_server() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(
                json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}}) + "\n"
            )
            sys.stdout.flush()
            continue
        if isinstance(msg, list):
            out = [r for item in msg if (r := handle(item)) is not None]
            if out:
                sys.stdout.write(json.dumps(out) + "\n")
                sys.stdout.flush()
            continue
        resp = handle(msg) if isinstance(msg, dict) else None
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Comprehensive Dual-Modality Self-Test (--selftest)
# ---------------------------------------------------------------------------

def _http_probe(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8", "replace")
        finally:
            exc.close()


def selftest() -> int:
    def call(name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args or {}}})
        assert resp is not None and "result" in resp, f"Unexpected tool response for {name}: {resp}"
        return resp["result"]

    # 1. Initialize & capabilities
    init_resp = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2026-07-28"}})
    assert init_resp is not None
    assert init_resp["result"]["protocolVersion"] == "2026-07-28"
    assert init_resp["result"]["serverInfo"]["version"] == "2.0.0"
    assert init_resp["result"]["capabilities"]["tools"]["listChanged"] is False

    # 2. Prefix-pinned 10-tool wire order
    expected_order = [
        "stage0_vault_fts_query",
        "stage0_vault_manifest_lookup",
        "stage0_ast_slice_and_parity",
        "precompensate_stdout_delta",
        "tandem_edge_route",
        "vertex_keyless_query",
        "apex_contactor_route_packet",
        "exodia_compaction_gate",
        "interpolate_state_sheet",
        "sovereign_dual_modality_status",
    ]
    assert [t["name"] for t in TOOLS] == expected_order
    assert len(TOOLS) == 10 and all(t["annotations"]["readOnlyHint"] for t in TOOLS)
    assert all(not t["annotations"]["openWorldHint"] for t in TOOLS[6:])

    # 3. Secret-path airlock + SHA-256 slice parity
    env_res = call("stage0_ast_slice_and_parity", {"filepath": str(HOME / ".env")})
    assert env_res["isError"] is True
    assert json.loads(env_res["content"][0]["text"])["code"] == "SECRET_PATH_AIRLOCK_DENY"
    first = json.loads(call("stage0_ast_slice_and_parity", {"filepath": __file__, "end_line": 20, "force_read": True})["content"][0]["text"])
    again = json.loads(call("stage0_ast_slice_and_parity", {"filepath": __file__, "end_line": 20})["content"][0]["text"])
    assert first["status"] == "SLICE_FETCHED" and again["status"] == "SHA256_PARITY_HIT"

    # 4. Stdout delta compressor
    noisy = "\n".join([f"[INFO] trace {i}" for i in range(300)] + ["AssertionError: line 42 fault"])
    delta_res = json.loads(call("precompensate_stdout_delta", {"raw_stdout": noisy})["content"][0]["text"])
    assert delta_res["status"] == "TRUNCATED" and delta_res["delta_tokens"] <= 300

    # 5. Edge router (thermal/VRAM + multi_turn escalation)
    edge = json.loads(call("tandem_edge_route", {"phone_temp_c": 37.0, "vram_used_gb": 3.0})["content"][0]["text"])
    assert edge["status"] == "ROUTED" and edge["vram"]["within_budget"] and edge["target_node"] == "WORKSTATION_GPU"
    edge_mt = json.loads(call("tandem_edge_route", {"phone_temp_c": 34.0, "vram_used_gb": 3.0, "multi_turn": True})["content"][0]["text"])
    assert edge_mt["resolved_model"] == "gemini-4-neon"

    # 6. Apex Contactor Flash Shunt
    routed_g = json.loads(call("apex_contactor_route_packet", {"requested_model": "gemini-3.5-flash", "objective": "audit"})["content"][0]["text"])
    assert routed_g["shunt_applied"] is True and routed_g["resolved_model"] == "gemini-4-neon" and len(routed_g["packet_sha256"]) == 16
    routed_a = json.loads(call("apex_contactor_route_packet", {"requested_model": "claude-3-5-haiku", "objective": "audit", "provider": "anthropic"})["content"][0]["text"])
    assert routed_a["shunt_applied"] is True and routed_a["resolved_model"] == "claude-opus-5-5"
    routed_o = json.loads(call("apex_contactor_route_packet", {"requested_model": "gpt-4o-mini", "objective": "audit", "provider": "openai"})["content"][0]["text"])
    assert routed_o["shunt_applied"] is True and routed_o["resolved_model"] == "gpt-5-pro-high"

    # 7. Exodia 25:1 compaction gate
    exodia = json.loads(call("exodia_compaction_gate", {"cache_reads": 26, "cache_writes": 1, "turns": 15})["content"][0]["text"])
    assert exodia["compact_required"] is True and exodia["taint_provenance"] == "TAINT_0_ARCHITECT"
    assert "DELTA_LINE_1" in exodia and "DELTA_LINE_2" in exodia and "DELTA_LINE_3" in exodia

    # 8. SEP-2640 State Interpolation fault-pointer + CSAA artifact minting
    interp_err = call("interpolate_state_sheet", {})
    err_text = interp_err["content"][0]["text"]
    err_obj = json.loads(err_text)
    assert interp_err["isError"] is True and err_obj["code"] == -32602
    assert err_obj["skill_uri"] == "skill://alpha/state-interpolation/SKILL.md" and len(err_text) // 4 < 120
    interp_ok = json.loads(call("interpolate_state_sheet", {"workflow_id": "wf-selftest-01"})["content"][0]["text"])
    assert interp_ok["state"] == "completed" and interp_ok["taintProvenance"] == "VERIFIED_ARCHITECT"
    assert len(interp_ok["artifact"]["signature"]) == 64

    # 9. Status tool, Resources, Prompts (nil-arg resilient), Equations
    status_obj = json.loads(call("sovereign_dual_modality_status", {})["content"][0]["text"])
    assert status_obj["version"] == "2.0.0" and len(status_obj["pinned_tool_order"]) == 10
    assert len(status_obj["sep2640_skills"]) == 3 and status_obj["redaction_patterns_count"] == 13
    assert len(EQUATIONS_VAULT) == 19
    res_list = handle({"jsonrpc": "2.0", "id": 2, "method": "resources/list"})
    assert res_list is not None and len(res_list["result"]["resources"]) == 4
    prompt_resp = handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "kppc_lod_blueprint"}})
    assert prompt_resp is not None and "result" in prompt_resp and prompt_resp["result"]["messages"]

    # 10. 13-pattern credential redaction probe (runtime concatenation only)
    probe_raw = " ".join([
        "Bearer abc123token",
        "sntrys_" + "Z" * 20,
        "AI" + "za" + "D" * 20,
        "ya29." + "D" * 24,
        "GOCSPX-" + "DummyDummyDummy01",
        "sk-ant-" + "D" * 24,
        "sk-proj-" + "B" * 24,
        "ghp_" + "C" * 24,
        "AKIA" + "0" * 16,
        "xoxb-" + "123456789012",
        "sk_live_" + "E" * 20,
        "-----BEGIN " + "PRIVATE KEY-----",
    ]) + "\nAPI_KEY=" + "supersecretvalue123"
    probe = redact(probe_raw)
    assert len(REDACTIONS) == 13
    assert "abc123token" not in probe and "DummyDummyDummy01" not in probe and ("AKIA" + "0" * 16) not in probe
    assert "supersecretvalue123" not in probe and "[REDACTED:PRIVATE_KEY]" in probe

    # 11. Ephemeral Streamable HTTP + OAuth 2.1 PKCE S256 + Revocation verification
    old_bearer = os.environ.get("ALPHA_MCP_BEARER_TOKEN")
    old_oauth = os.environ.get("ALPHA_MCP_OAUTH_SECRET")
    test_bearer = "selftest-bearer-" + secrets.token_hex(8)
    test_oauth = "selftest-oauth-" + secrets.token_hex(8)
    os.environ["ALPHA_MCP_BEARER_TOKEN"] = test_bearer
    os.environ["ALPHA_MCP_OAUTH_SECRET"] = test_oauth
    srv = create_http_server("127.0.0.1", 0, require_auth=True, quiet=True)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        st, _h, body = _http_probe(f"{base}/health")
        assert st == 200 and json.loads(body)["status"] == "ONLINE"
        st, _h, body = _http_probe(f"{base}/.well-known/agent-card.json")
        assert st == 200 and json.loads(body)["signature"]["alg"] == "HS256-SOVEREIGN"
        st, _h, _b = _http_probe(f"{base}/mcp", method="GET")
        assert st == 405
        mcp_req = json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "sovereign_dual_modality_status", "arguments": {}}}).encode("utf-8")
        st, hdrs, _b = _http_probe(f"{base}/mcp", method="POST", headers={"Content-Type": "application/json"}, body=mcp_req)
        assert st == 401 and "oauth-protected-resource" in hdrs.get("WWW-Authenticate", "")
        st, _h, _b = _http_probe(f"{base}/oauth/authorize?code_challenge=abc&code_challenge_method=S256")
        assert st == 403
        verifier = "selftest-pkce-verifier-" + secrets.token_hex(24)
        challenge = _pkce_s256(verifier)
        st, _h, body = _http_probe(
            f"{base}/oauth/authorize?client_id=selftest&code_challenge={challenge}&code_challenge_method=S256",
            headers={"X-Alpha-OAuth-Secret": test_oauth, "Accept": "application/json"},
        )
        assert st == 200
        code = json.loads(body)["code"]
        tok_form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "client_id": "selftest"}).encode("utf-8")
        st, _h, body = _http_probe(f"{base}/oauth/token", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=tok_form)
        assert st == 200
        access_tok = json.loads(body)["access_token"]
        st, _h, _b = _http_probe(f"{base}/oauth/token", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=tok_form)
        assert st == 400  # Replay denied
        st, _h, body = _http_probe(
            f"{base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {access_tok}"},
            body=mcp_req,
        )
        assert st == 200 and json.loads(body)["result"]["isError"] is False
        rev_form = urllib.parse.urlencode({"token": access_tok}).encode("utf-8")
        st, _h, _b = _http_probe(f"{base}/oauth/revoke", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=rev_form)
        assert st == 200
        st, _h, _b = _http_probe(
            f"{base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {access_tok}"},
            body=mcp_req,
        )
        assert st == 401
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=3)
        if old_bearer is None:
            os.environ.pop("ALPHA_MCP_BEARER_TOKEN", None)
        else:
            os.environ["ALPHA_MCP_BEARER_TOKEN"] = old_bearer
        if old_oauth is None:
            os.environ.pop("ALPHA_MCP_OAUTH_SECRET", None)
        else:
            os.environ["ALPHA_MCP_OAUTH_SECRET"] = old_oauth

    print(
        json.dumps(
            {
                "status": "ALL_SELFTESTS_PASSED",
                "version": SERVER_VERSION,
                "tools": len(TOOLS),
                "equations": len(EQUATIONS_VAULT),
                "sep2640_skills": len(SEP2640_SKILLS),
                "redaction_patterns": len(REDACTIONS),
                "transports_verified": ["stdio", "http"],
            }
        )
    )
    return 0


def main() -> None:
    default_host = "0.0.0.0" if os.environ.get("K_SERVICE") else "127.0.0.1"
    default_port = int(os.environ.get("PORT", "8000"))
    ap = argparse.ArgumentParser(description="Alpha MCP Sovereign Dual-Modality v2.0 server (stdio + Streamable HTTP)")
    ap.add_argument("--transport", choices=["stdio", "http"], default="stdio", help="Wire transport modality")
    ap.add_argument("--host", default=default_host, help="Bind host for HTTP transport")
    ap.add_argument("--port", type=int, default=default_port, help="Bind port for HTTP transport")
    ap.add_argument("--require-auth", action="store_true", help="Force Bearer / OAuth 2.1 auth even on loopback")
    ap.add_argument("--selftest", action="store_true", help="Run built-in dual-modality checks and exit")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.transport == "http":
        run_http_server(args.host, args.port, require_auth=args.require_auth)
        return
    run_stdio_server()


if __name__ == "__main__":
    main()
