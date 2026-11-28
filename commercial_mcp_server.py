#!/usr/bin/env python3
"""Eloquent Commercial MCP Server (v1.0.0 — Sanitized Zero-Privilege Public Plane).

Air-gapped commercial Streamable HTTP MCP server designed to sit behind the
Cloudflare Edge Paywall Gateway (`https://api.eloquentwin.com/mcp`).

Security invariants:
  - Zero private vault, zero GCS/BigQuery/Vertex access, zero host filesystem reads.
  - All 7 tools are 100% deterministic pure Python ($0 marginal AI COGS) with
    recursive secret redaction on every outbound payload.
  - Fail-closed origin lock: requires `X-Eloquent-Edge-Secret` matching
    `ELOQUENT_EDGE_SHARED_SECRET` on all `/mcp` traffic so direct `.run.app`
    requests cannot bypass the Cloudflare subscription paywall.
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socketserver
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SERVER_NAME = "eloquent-mcp-commercial"
SERVER_VERSION = "1.0.0"
WORKBENCH_URI = "ui://eloquent-mcp/workbench.html"
SUPPORTED_PROTOCOL_VERSIONS: list[str] = [
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
]
MAX_BODY_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 256 * 1024
MAX_SLICE_LINES = 160

_SELF_PATH = Path(__file__).resolve()
BOOT_CODE_SHA256 = hashlib.sha256(_SELF_PATH.read_bytes()).hexdigest()
_EPHEMERAL_HMAC_KEY = secrets.token_bytes(32)

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("GCP_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("ELOQUENT_KEY", re.compile(r"\belq_(?:live|test)_[0-9a-fA-F]{24,}\b")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("BEARER_HEADER", re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9_\-\.=]{16,}")),
    ("GENERIC_SECRET_KV", re.compile(r"(?i)\b(api_key|client_secret|access_token|refresh_token|password|secret_key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{12,})['\"]?")),
    ("LOCAL_USER_PATH", re.compile(r"(?i)(?:[A-Z]:\\Users\\|/Users/|/home/)[^\\/\s'\"]+")),
]

_BANNED_TIER_RE = re.compile(r"(?i)(?:^|[-_\s(])(flash|lite|mini|haiku|nano)(?:$|[-_\s)])|^gemini-2\.5-|^gemini-4-hydrogen-(?:low|medium|high)$")
_FAULT_LINE_RE = re.compile(r"(?i)(error|exception|traceback|failed|fatal|assert|panic|timeout|denied|refused|exit code [1-9]|status [45]\d\d)")
_ANN_RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def _runtime_parity() -> dict[str, Any]:
    try:
        disk = hashlib.sha256(_SELF_PATH.read_bytes()).hexdigest()
    except OSError:
        disk = ""
    return {
        "boot_code_sha256": BOOT_CODE_SHA256,
        "disk_code_sha256": disk,
        "runtime_parity_ok": bool(disk and hmac.compare_digest(BOOT_CODE_SHA256, disk)),
    }


def redact_text(text: str) -> str:
    out = str(text)
    for label, pat in _SECRET_PATTERNS:
        if label == "LOCAL_USER_PATH":
            out = pat.sub("~", out)
        elif label == "GENERIC_SECRET_KV":
            out = pat.sub(r"\1=[REDACTED]", out)
        else:
            out = pat.sub(f"[REDACTED:{label}]", out)
    return out


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): redact_obj(v) for k, v in obj.items()}
    return obj


def negotiate_protocol_version(requested: str | None) -> str:
    req = str(requested or "").strip()
    if req in SUPPORTED_PROTOCOL_VERSIONS:
        return req
    return SUPPORTED_PROTOCOL_VERSIONS[0]


def tool_stage0_ast_slice_inline(
    source_code: str,
    language: str = "python",
    start_line: int = 1,
    end_line: int = 160,
    label: str = "inline",
) -> dict[str, Any]:
    raw = str(source_code or "")
    if len(raw.encode("utf-8")) > MAX_SOURCE_BYTES:
        return {"status": "ERROR", "error": f"source_code exceeds {MAX_SOURCE_BYTES} byte limit"}
    lines = raw.splitlines()
    total = len(lines)
    s = max(1, int(start_line or 1))
    e = min(total, max(s, int(end_line or (s + MAX_SLICE_LINES - 1))))
    if (e - s + 1) > MAX_SLICE_LINES:
        e = s + MAX_SLICE_LINES - 1
    sliced = "\n".join(f"{i}: {lines[i - 1]}" for i in range(s, e + 1)) if total else ""
    safe_slice = redact_text(sliced)
    symbols: list[dict[str, Any]] = []
    lang = str(language or "text").strip().lower()
    if lang == "python" and raw.strip():
        try:
            tree = ast.parse(raw)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    symbols.append({
                        "kind": type(node).__name__,
                        "name": node.name,
                        "line": int(getattr(node, "lineno", 0)),
                        "end_line": int(getattr(node, "end_lineno", 0) or 0),
                    })
        except SyntaxError as exc:
            symbols.append({"kind": "SyntaxWarning", "name": f"line {exc.lineno}: {exc.msg}", "line": int(exc.lineno or 0)})
    digest = hashlib.sha256(safe_slice.encode("utf-8")).hexdigest()
    return {
        "status": "OK",
        "label": redact_text(label)[:80],
        "language": lang,
        "total_lines": total,
        "slice_range": [s, e],
        "slice_sha256_16": digest[:16],
        "symbols_count": len(symbols),
        "symbols": symbols[:40],
        "content": safe_slice,
    }


def tool_precompensate_stdout_delta(raw_stdout: str, command_label: str = "command") -> dict[str, Any]:
    text = redact_text(str(raw_stdout or ""))
    lines = text.splitlines()
    est_in_tokens = max(1, len(text) // 4)
    faults = [f"L{idx}: {ln.strip()}" for idx, ln in enumerate(lines, 1) if _FAULT_LINE_RE.search(ln)]
    if not faults:
        tail = [f"L{idx}: {ln.strip()}" for idx, ln in enumerate(lines[-6:], max(1, len(lines) - 5))]
        delta = "\n".join(tail)
        verdict = "CLEAN_NO_FAULTS"
    else:
        delta = "\n".join(faults[:18])
        verdict = "FAULTS_EXTRACTED"
    if len(delta) > 1100:
        delta = delta[:1097] + "..."
    est_out_tokens = max(1, len(delta) // 4)
    ratio = round(est_in_tokens / max(1, est_out_tokens), 2)
    return {
        "status": "OK",
        "command_label": redact_text(command_label)[:80],
        "verdict": verdict,
        "input_lines": len(lines),
        "fault_lines_found": len(faults),
        "estimated_tokens_in": est_in_tokens,
        "estimated_tokens_out": est_out_tokens,
        "compression_ratio": ratio,
        "delta_sha256_16": hashlib.sha256(delta.encode("utf-8")).hexdigest()[:16],
        "fault_delta": delta,
    }


def tool_apex_contactor_route_packet(
    requested_model: str = "gemini-4-carbon",
    objective: str = "",
    provider: str = "google",
    floor_model: str = "gemini-4-hydrogen-xhigh",
    apex_model: str = "gemini-4-carbon",
) -> dict[str, Any]:
    req = str(requested_model or "").strip() or apex_model
    shunt_applied = bool(_BANNED_TIER_RE.search(req))
    resolved = apex_model if shunt_applied else req
    obj_clean = redact_text(str(objective or ""))[:1200]
    packet_digest = hashlib.sha256(f"{provider}|{resolved}|{obj_clean}".encode("utf-8")).hexdigest()[:16]
    return {
        "status": "OK",
        "provider": str(provider or "google").strip().lower(),
        "requested_model": req,
        "resolved_model": resolved,
        "shunt_applied": shunt_applied,
        "minimum_floor": floor_model,
        "lod_escalation_budget_tokens": 6000,
        "packet_sha256_16": packet_digest,
        "objective_summary": obj_clean,
    }


def tool_exodia_compaction_gate(
    cache_reads: int,
    cache_writes: int,
    turns: int = 1,
    verified_invariant: str = "",
    force_compact: bool = False,
) -> dict[str, Any]:
    reads = max(0, int(cache_reads or 0))
    writes = max(1, int(cache_writes or 1))
    turn_count = max(0, int(turns or 0))
    ratio = round(reads / writes, 2)
    should_compact = bool(force_compact or ratio >= 25.0 or turn_count >= 15)
    inv_clean = redact_text(str(verified_invariant or "zero-drift-state"))[:200]
    state_hash = hashlib.sha256(f"{reads}:{writes}:{turn_count}:{inv_clean}".encode("utf-8")).hexdigest()[:16]
    return {
        "status": "OK",
        "action": "COMPACT_NOW" if should_compact else "HOLD_PREFIX",
        "cache_read_write_ratio": ratio,
        "ratio_threshold": 25.0,
        "turns": turn_count,
        "turn_threshold": 15,
        "state_delta_sha256_16": state_hash,
        "three_line_delta": [
            f"INVARIANT: {inv_clean}",
            f"CACHE_RATIO: {ratio}:1 (reads={reads}, writes={writes}, turns={turn_count})",
            f"STATE_HASH: {state_hash} | ACTION={'EVICT_LOD2_KEEP_LOD1' if should_compact else 'KEEP_LIVE'}",
        ],
    }


def tool_interpolate_state_sheet(
    workflow_id: str,
    act_open: str,
    act_mid: str,
    act_exit: str,
    assertions: list[str] | None = None,
) -> dict[str, Any]:
    wf = redact_text(str(workflow_id or "workflow"))[:80]
    sheet = {
        "workflow_id": wf,
        "acts": {
            "act_1_open": redact_text(str(act_open or ""))[:400],
            "act_2_mid": redact_text(str(act_mid or ""))[:400],
            "act_3_exit": redact_text(str(act_exit or ""))[:400],
        },
        "mechanical_assertions": [redact_text(str(a))[:200] for a in (assertions or [])[:12]],
        "signed_at_epoch": int(time.time()),
    }
    canonical = json.dumps(sheet, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_EPHEMERAL_HMAC_KEY, canonical, hashlib.sha256).hexdigest()[:24]
    return {"status": "OK", "state_sheet": sheet, "hmac_sha256_24": sig}


def tool_tandem_edge_route(
    task_type: str = "coding",
    device_temp_c: float = 34.0,
    vram_used_gb: float = 3.0,
    vram_total_gb: float = 8.0,
    multi_turn: bool = False,
) -> dict[str, Any]:
    temp = float(device_temp_c)
    t = max(0.0, min(1.0, (temp - 32.0) / 10.0))
    thermal_pressure = round(6 * (t**5) - 15 * (t**4) + 10 * (t**3), 4)
    vram_ratio = round(max(0.0, float(vram_used_gb)) / max(0.5, float(vram_total_gb)), 3)
    escalate = bool(multi_turn or thermal_pressure >= 0.7 or vram_ratio >= 0.85)
    return {
        "status": "OK",
        "task_type": redact_text(str(task_type or "coding"))[:40],
        "route": "CLOUD_STAGE_APEX" if escalate else "LOCAL_STAGE_0_EDGE",
        "thermal_pressure_c2": thermal_pressure,
        "vram_utilization": vram_ratio,
        "reason": "Escalated to cloud frontier due to multi-turn/thermal/VRAM headroom." if escalate else "Safe for local Stage-0/edge execution.",
    }


def tool_pulse_analyze_payload(
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
    turns: int = 1,
    rate_input_per_mtok_usd: float = 3.0,
    rate_cache_read_per_mtok_usd: float = 0.30,
) -> dict[str, Any]:
    inp = max(0, int(input_tokens or 0))
    out = max(0, int(output_tokens or 0))
    cr = max(0, int(cache_read_tokens or 0))
    cw = max(0, int(cache_write_tokens or 0))
    t_cnt = max(1, int(turns or 1))
    total_prompt = max(1, inp + cr + cw)
    hit_pct = round((cr / total_prompt) * 100.0, 2)
    reuse = round(cr / max(1, cw), 2) if cw > 0 else 0.0
    saved_usd = round((cr / 1_000_000.0) * max(0.0, float(rate_input_per_mtok_usd) - float(rate_cache_read_per_mtok_usd)), 4)
    findings: list[str] = []
    if hit_pct < 75.0:
        findings.append("Cache hit rate below 75%: stabilize static system prompt prefix and pin tool schemas in deterministic order.")
    if cw > 0 and reuse < 5.0:
        findings.append("Low cache reuse (<5x): reduce mid-turn dynamic prompt mutations and batch parallel tool calls.")
    if t_cnt >= 20:
        findings.append("Long session (>=20 turns): run exodia_compaction_gate to evict stale working slices.")
    if not findings:
        findings.append("Prefix caching is healthy; maintain static tool ordering and LOD 0-1-2 slicing.")
    return {
        "status": "OK",
        "total_tokens": inp + out + cr + cw,
        "cache_hit_rate_pct": hit_pct,
        "cache_reuse_multiplier": reuse,
        "estimated_cache_savings_usd": saved_usd,
        "turns": t_cnt,
        "diagnostics": findings,
    }


TOOLS: list[dict[str, Any]] = [
    {
        "name": "stage0_ast_slice_inline",
        "description": "Slice up to 160 lines of inline source text with Python AST symbol headers, SHA-256 parity digest, and automatic secret redaction (zero host disk reads).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {"type": "string", "description": "Inline source code or text to slice (max 256 KB)."},
                "language": {"type": "string", "default": "python"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "default": 160},
                "label": {"type": "string", "default": "inline"},
            },
            "required": ["source_code"],
        },
        "annotations": _ANN_RO,
        "_meta": {"ui": {"resourceUri": WORKBENCH_URI}},
    },
    {
        "name": "precompensate_stdout_delta",
        "description": "Compress noisy build/test stdout (>500 tokens) into a redacted <300-token fault-only delta.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "raw_stdout": {"type": "string", "description": "Raw command/build/test output to compress."},
                "command_label": {"type": "string", "default": "command"},
            },
            "required": ["raw_stdout"],
        },
        "annotations": _ANN_RO,
        "_meta": {"ui": {"resourceUri": WORKBENCH_URI}},
    },
    {
        "name": "apex_contactor_route_packet",
        "description": "Enforce model floor / Flash-shunt routing and emit a compact SHA-256-indexed escalation packet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "requested_model": {"type": "string", "default": "gemini-4-carbon"},
                "objective": {"type": "string", "default": ""},
                "provider": {"type": "string", "default": "google"},
            },
        },
        "annotations": _ANN_RO,
        "_meta": {"ui": {"resourceUri": WORKBENCH_URI}},
    },
    {
        "name": "exodia_compaction_gate",
        "description": "Evaluate Cache_Reads/Cache_Writes >= 25:1 or turn threshold and emit a 3-line SHA-256 compaction delta.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cache_reads": {"type": "integer"},
                "cache_writes": {"type": "integer"},
                "turns": {"type": "integer", "default": 1},
                "verified_invariant": {"type": "string", "default": ""},
                "force_compact": {"type": "boolean", "default": False},
            },
            "required": ["cache_reads", "cache_writes"],
        },
        "annotations": _ANN_RO,
        "_meta": {"ui": {"resourceUri": WORKBENCH_URI}},
    },
    {
        "name": "interpolate_state_sheet",
        "description": "Generate an HMAC-SHA256 signed 3-Act state transition contact sheet for deterministic verification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workflow_id": {"type": "string"},
                "act_open": {"type": "string"},
                "act_mid": {"type": "string"},
                "act_exit": {"type": "string"},
                "assertions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["workflow_id", "act_open", "act_mid", "act_exit"],
        },
        "annotations": _ANN_RO,
    },
    {
        "name": "tandem_edge_route",
        "description": "C2 smootherstep thermal (32-42C) and VRAM headroom edge-vs-cloud router.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_type": {"type": "string", "default": "coding"},
                "device_temp_c": {"type": "number", "default": 34.0},
                "vram_used_gb": {"type": "number", "default": 3.0},
                "vram_total_gb": {"type": "number", "default": 8.0},
                "multi_turn": {"type": "boolean", "default": False},
            },
        },
        "annotations": _ANN_RO,
    },
    {
        "name": "pulse_analyze_payload",
        "description": "Compute prompt cache hit rate, cache reuse multiplier, estimated USD savings, and leak diagnostics from a scrubbed usage payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_tokens": {"type": "integer"},
                "output_tokens": {"type": "integer"},
                "cache_read_tokens": {"type": "integer", "default": 0},
                "cache_write_tokens": {"type": "integer", "default": 0},
                "turns": {"type": "integer", "default": 1},
            },
            "required": ["input_tokens", "output_tokens"],
        },
        "annotations": _ANN_RO,
        "_meta": {"ui": {"resourceUri": WORKBENCH_URI}},
    },
]

PROMPTS: list[dict[str, Any]] = [
    {
        "name": "kppc_lod_blueprint",
        "description": "Structure a technical system design into progressive LOD 0-1-2 slices.",
        "arguments": [{"name": "objective", "description": "System objective", "required": False}],
    },
    {
        "name": "exodia_zero_drag_audit",
        "description": "Audit prompt cache efficiency, stdout noise, and compaction thresholds.",
        "arguments": [{"name": "scope", "description": "Workflow or pipeline scope", "required": False}],
    },
    {
        "name": "paywall_mcp_quickstart",
        "description": "Return sanitized connection instructions for Eloquent Commercial MCP.",
        "arguments": [],
    },
]

WORKBENCH_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Eloquent Commercial MCP Workbench</title>
<style>
  :root { color-scheme: dark; --bg:#090c12; --card:#121824; --bd:#243045; --fg:#eef3fa; --muted:#97a8c2; --ac:#5ea0ff; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,sans-serif; background:var(--bg); color:var(--fg); padding:20px; }
  .wrap { max-width:780px; margin:0 auto; }
  .card { background:var(--card); border:1px solid var(--bd); border-radius:16px; padding:20px; margin-bottom:14px; }
  h1 { margin:0 0 6px; font-size:1.25rem; }
  p { margin:0; color:var(--muted); font-size:.92rem; line-height:1.5; }
  ul { margin:12px 0 0; padding-left:18px; color:#d7e3f5; font-size:.9rem; line-height:1.65; }
  code { background:#1b2436; padding:2px 6px; border-radius:6px; font-size:.84rem; }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Eloquent Commercial MCP Workbench (v1.0.0)</h1>
    <p>Sanitized zero-privilege Streamable HTTP MCP suite running behind Cloudflare Edge paywall metering.</p>
    <ul>
      <li><code>stage0_ast_slice_inline</code> — 160-line inline AST slicer with SHA-256 dedup &amp; redaction</li>
      <li><code>precompensate_stdout_delta</code> — fault-only &lt;300-token log compressor</li>
      <li><code>apex_contactor_route_packet</code> — model floor &amp; Flash-shunt router</li>
      <li><code>exodia_compaction_gate</code> — 25:1 cache-drag compaction evaluator</li>
      <li><code>interpolate_state_sheet</code> — HMAC-signed 3-Act verification sheet</li>
      <li><code>tandem_edge_route</code> — C2 thermal &amp; VRAM edge router</li>
      <li><code>pulse_analyze_payload</code> — prompt cache savings &amp; leak diagnostics</li>
    </ul>
  </div>
</div>
</body>
</html>
"""


def dispatch_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    a = args if isinstance(args, dict) else {}
    if name == "stage0_ast_slice_inline":
        res = tool_stage0_ast_slice_inline(
            source_code=str(a.get("source_code") or ""),
            language=str(a.get("language") or "python"),
            start_line=int(a.get("start_line") or 1),
            end_line=int(a.get("end_line") or 160),
            label=str(a.get("label") or "inline"),
        )
    elif name == "precompensate_stdout_delta":
        res = tool_precompensate_stdout_delta(
            raw_stdout=str(a.get("raw_stdout") or ""),
            command_label=str(a.get("command_label") or "command"),
        )
    elif name == "apex_contactor_route_packet":
        res = tool_apex_contactor_route_packet(
            requested_model=str(a.get("requested_model") or "gemini-4-carbon"),
            objective=str(a.get("objective") or ""),
            provider=str(a.get("provider") or "google"),
        )
    elif name == "exodia_compaction_gate":
        res = tool_exodia_compaction_gate(
            cache_reads=int(a.get("cache_reads") or 0),
            cache_writes=int(a.get("cache_writes") or 1),
            turns=int(a.get("turns") or 1),
            verified_invariant=str(a.get("verified_invariant") or ""),
            force_compact=bool(a.get("force_compact") or False),
        )
    elif name == "interpolate_state_sheet":
        res = tool_interpolate_state_sheet(
            workflow_id=str(a.get("workflow_id") or "workflow"),
            act_open=str(a.get("act_open") or ""),
            act_mid=str(a.get("act_mid") or ""),
            act_exit=str(a.get("act_exit") or ""),
            assertions=a.get("assertions") if isinstance(a.get("assertions"), list) else [],
        )
    elif name == "tandem_edge_route":
        res = tool_tandem_edge_route(
            task_type=str(a.get("task_type") or "coding"),
            device_temp_c=float(a.get("device_temp_c") or 34.0),
            vram_used_gb=float(a.get("vram_used_gb") or 3.0),
            vram_total_gb=float(a.get("vram_total_gb") or 8.0),
            multi_turn=bool(a.get("multi_turn") or False),
        )
    elif name == "pulse_analyze_payload":
        res = tool_pulse_analyze_payload(
            input_tokens=int(a.get("input_tokens") or 0),
            output_tokens=int(a.get("output_tokens") or 0),
            cache_read_tokens=int(a.get("cache_read_tokens") or 0),
            cache_write_tokens=int(a.get("cache_write_tokens") or 0),
            turns=int(a.get("turns") or 1),
        )
    else:
        raise KeyError(f"Unknown commercial tool: {name}")
    return redact_obj(res)


def handle_jsonrpc(req: dict[str, Any], tier: str = "pro") -> dict[str, Any] | None:
    req_id = req.get("id")
    method = str(req.get("method") or "")
    params = req.get("params") if isinstance(req.get("params"), dict) else {}

    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "initialize":
        proto = negotiate_protocol_version(params.get("protocolVersion"))
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": proto,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        tname = str(params.get("name") or "")
        targs = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        try:
            data = dispatch_tool(tname, targs)
        except KeyError as exc:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": str(exc)}}
        except (ValueError, TypeError) as exc:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(exc)}}
        data["commercial_tier"] = tier
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(data, indent=2)}],
                "structuredContent": data,
            },
        }
    if method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "resources": [
                    {
                        "uri": WORKBENCH_URI,
                        "name": "Eloquent Commercial MCP Workbench",
                        "description": "Sanitized interactive SEP-1865 workbench UI.",
                        "mimeType": "text/html;profile=mcp-app",
                    }
                ]
            },
        }
    if method == "resources/read":
        uri = str(params.get("uri") or "")
        if uri == WORKBENCH_URI:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {"uri": WORKBENCH_URI, "mimeType": "text/html;profile=mcp-app", "text": WORKBENCH_HTML}
                    ]
                },
            }
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown resource URI: {uri}"}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": PROMPTS}}
    if method == "prompts/get":
        pname = str(params.get("name") or "")
        pargs = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if pname == "kppc_lod_blueprint":
            obj = redact_text(str(pargs.get("objective") or "<your system objective>"))
            text = f"Decompose '{obj}' into LOD 0 (objective & invariants), LOD 1 (contracts & schemas), and LOD 2 (transient implementation slices <=160 lines)."
        elif pname == "exodia_zero_drag_audit":
            sc = redact_text(str(pargs.get("scope") or "<current session>"))
            text = f"Run pulse_analyze_payload and exodia_compaction_gate for '{sc}', compress noisy command output with precompensate_stdout_delta, and report exact cache savings."
        elif pname == "paywall_mcp_quickstart":
            text = "Connect any MCP 2026-07-28/2025-11-25 client to https://api.eloquentwin.com/mcp with header 'Authorization: Bearer elq_live_<your-key>'."
        else:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown prompt: {pname}"}}
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "description": pname,
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            },
        }
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


class CommercialMCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class CommercialHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("COMMERCIAL_MCP_QUIET") == "1":
            return
        sys.stderr.write(f"[commercial-mcp] {fmt % args}\n")

    def _base_url(self) -> str:
        proto = (self.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip()
        host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "api.eloquentwin.com").split(",")[0].strip()
        if proto not in ("http", "https"):
            proto = "https"
        return f"{proto}://{host}"

    def _send_json(self, code: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _check_edge_origin_lock(self) -> tuple[bool, str]:
        expected = os.environ.get("ELOQUENT_EDGE_SHARED_SECRET", "").strip()
        if not expected:
            # Fail closed on Cloud Run (K_SERVICE set) if edge secret was omitted
            if os.environ.get("K_SERVICE"):
                return False, "server_unconfigured"
            return True, "local_dev"
        got = (self.headers.get("X-Eloquent-Edge-Secret") or "").strip()
        if not got or not hmac.compare_digest(got, expected):
            return False, "edge_gateway_required"
        tier = (self.headers.get("X-Eloquent-Tier") or "pro").strip().lower()
        return True, tier

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        route = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        base = self._base_url()
        if route in ("/", "/health"):
            self._send_json(
                200,
                {
                    "status": "ONLINE",
                    "server": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "profile": "sanitized_public_commercial",
                    "zero_disk_vault": True,
                    "tools_count": len(TOOLS),
                    "prompts_count": len(PROMPTS),
                    "mcp_endpoint": f"{base}/mcp",
                    "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
                    **_runtime_parity(),
                },
            )
            return
        if route == "/.well-known/oauth-protected-resource":
            self._send_json(
                200,
                {
                    "resource": f"{base}/mcp",
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["mcp:commercial:read", "mcp:commercial:tools"],
                    "resource_documentation": "https://eloquentwin.com/#pricing",
                },
            )
            return
        if route == "/mcp":
            ok, reason = self._check_edge_origin_lock()
            if not ok:
                self._send_json(
                    403,
                    {"error": reason, "message": "Access this commercial MCP via https://api.eloquentwin.com/mcp with an active subscription key."},
                )
                return
            self._send_json(405, {"error": "use_post_mcp", "mcp_endpoint": f"{base}/mcp"})
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        route = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        if route != "/mcp":
            self._send_json(404, {"error": "not_found"})
            return
        ok, tier_or_err = self._check_edge_origin_lock()
        if not ok:
            self._send_json(
                403,
                {"error": tier_or_err, "message": "Direct origin calls are blocked; connect via https://api.eloquentwin.com/mcp."},
            )
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(400, {"error": "invalid_content_length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "payload_too_large"})
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
            return
        resp = handle_jsonrpc(body, tier=tier_or_err)
        if resp is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_json(200, resp)


def run_selftest() -> int:
    assert len(TOOLS) == 7
    assert all(t["annotations"]["readOnlyHint"] is True for t in TOOLS)
    for proto in SUPPORTED_PROTOCOL_VERSIONS:
        init = handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": proto}})
        assert init and init["result"]["protocolVersion"] == proto
    for p in PROMPTS:
        pr = handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "prompts/get", "params": {"name": p["name"]}})
        assert pr and "messages" in pr["result"]
    fake_gcp_key = "AIza" + "SyA" + ("1" * 32)
    sl = dispatch_tool("stage0_ast_slice_inline", {"source_code": f"def f():\n    return '{fake_gcp_key}'\n"})
    assert sl["status"] == "OK" and fake_gcp_key not in sl["content"] and "[REDACTED:GCP_API_KEY]" in sl["content"]
    shunt = dispatch_tool("apex_contactor_route_packet", {"requested_model": "gemini-3.8-flash", "objective": "test"})
    assert shunt["shunt_applied"] is True and shunt["resolved_model"] == "gemini-4-carbon"
    pulse = dispatch_tool("pulse_analyze_payload", {"input_tokens": 10000, "output_tokens": 2000, "cache_read_tokens": 90000, "cache_write_tokens": 5000, "turns": 8})
    assert pulse["cache_hit_rate_pct"] > 80.0
    parity = _runtime_parity()
    assert parity["runtime_parity_ok"] is True
    print(json.dumps({"status": "COMMERCIAL_SELFTEST_PASSED", "server": SERVER_NAME, "version": SERVER_VERSION, "tools": len(TOOLS), "prompts": len(PROMPTS), **parity}))
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return run_selftest()
    port = int(os.environ.get("PORT", "8080"))
    srv = CommercialMCPServer(("0.0.0.0", port), CommercialHandler)
    sys.stderr.write(f"[{SERVER_NAME}] listening on 0.0.0.0:{port} (tools={len(TOOLS)})\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
