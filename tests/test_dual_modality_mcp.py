#!/usr/bin/env python3
"""End-to-end dual-modality test suite for Sovereign Dual-Modality MCP v2.0.

Covers:
1. Real `--transport stdio` subprocess JSON-RPC 2.0 protocol, 10 prefix-pinned tools,
   nil-arg resilient prompts, 4 MCP resources, secret-path airlock, SHA-256 slice parity,
   Apex Contactor Flash Shunt, Exodia 25:1 gate, SEP-2640 fault pointer & CSAA artifact
   minting, and 13-pattern redaction sieve.
2. Real `--transport http --host 127.0.0.1 --port <free_port> --require-auth` Streamable HTTP
   server with discovery endpoints, signed Google A2A v1.0.1 Agent Card, fail-closed auth
   airlock (both `--require-auth` and remote forwarding headers), Bearer auth, OAuth 2.1 PKCE
   S256 authorize -> token -> MCP call -> single-use code replay block -> refresh rotation ->
   RFC 7009 revocation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_SCRIPT = REPO_ROOT / "alpha_mcp_server.py"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import alpha_mcp_server as srv_mod  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _pkce_s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _http_call(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    follow_redirects: bool = True,
) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(req, timeout=8) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8", "replace")
        finally:
            exc.close()


class TestStdioModalityE2E(unittest.TestCase):
    """Spawns alpha_mcp_server.py as a real --transport stdio subprocess."""

    def setUp(self) -> None:
        env = os.environ.copy()
        env.pop("GOOGLE_CLOUD_PROJECT", None)
        env.pop("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", None)
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT), "--transport", "stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
        )
        self._req_id = 0

    def tearDown(self) -> None:
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        if self.proc.stdout and not self.proc.stdout.closed:
            self.proc.stdout.close()
        if self.proc.stderr and not self.proc.stderr.closed:
            self.proc.stderr.close()

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self._req_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        self.assertTrue(line.strip(), f"Empty stdout response for {method}")
        resp = json.loads(line)
        self.assertEqual(resp["id"], self._req_id)
        return resp

    def _tool_call(self, name: str, arguments: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool, str]:
        resp = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        self.assertIn("result", resp, f"RPC error for {name}: {resp}")
        result = resp["result"]
        raw_text = result["content"][0]["text"]
        return json.loads(raw_text), bool(result.get("isError")), raw_text

    def test_stdio_full_contract(self) -> None:
        # 1. Initialize & protocol version negotiation
        init = self._rpc("initialize", {"protocolVersion": "2026-07-28"})
        self.assertEqual(init["result"]["protocolVersion"], "2026-07-28")
        self.assertEqual(init["result"]["serverInfo"], {"name": "alpha-mcp", "version": "2.0.0"})
        self.assertIs(init["result"]["capabilities"]["tools"]["listChanged"], False)
        self.assertIn("resources", init["result"]["capabilities"])
        self.assertIn("prompts", init["result"]["capabilities"])

        # Send notification (must not emit a response line)
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()

        # 2. Exact 10-tool prefix-pinned wire order
        tl = self._rpc("tools/list")
        tools = tl["result"]["tools"]
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
        self.assertEqual([t["name"] for t in tools], expected_order)
        for tool in tools[6:]:
            ann = tool["annotations"]
            self.assertTrue(ann["readOnlyHint"])
            self.assertFalse(ann["destructiveHint"])
            self.assertTrue(ann["idempotentHint"])
            self.assertFalse(ann["openWorldHint"])

        # 3. Prompts list & nil-arg resilience (omitted, None, empty dict)
        pl = self._rpc("prompts/list")
        prompt_names = [p["name"] for p in pl["result"]["prompts"]]
        self.assertEqual(prompt_names, ["kppc_lod_blueprint", "exodia_zero_drag_audit", "zero_cost_online_deploy"])
        for pname in prompt_names:
            for arg_variant in (None, {}):
                params = {"name": pname} if arg_variant is None else {"name": pname, "arguments": arg_variant}
                pg = self._rpc("prompts/get", params)
                self.assertIn("result", pg, f"prompts/get failed for {pname} with {arg_variant}: {pg}")
                self.assertTrue(pg["result"]["messages"][0]["content"]["text"])
        pg_null = self._rpc("prompts/get", {"name": "kppc_lod_blueprint", "arguments": None})
        self.assertIn("result", pg_null)

        # 4. Resources list & read
        rl = self._rpc("resources/list")
        uris = [r["uri"] for r in rl["result"]["resources"]]
        self.assertEqual(
            uris,
            [
                "alpha://genesis/anchor-t0",
                "alpha://vault/manifest-summary",
                "alpha://hosting/zero-cost-blueprint",
                "alpha://telemetry/exodia-ledger",
                "ui://alpha-mcp/workbench.html",
            ],
        )
        app_rr = self._rpc("resources/read", {"uri": "ui://alpha-mcp/workbench.html"})
        app_item = app_rr["result"]["contents"][0]
        self.assertEqual(app_item["mimeType"], "text/html;profile=mcp-app")
        self.assertIn("<!DOCTYPE html>", app_item["text"])
        self.assertLess(len(app_item["text"].encode("utf-8")), 10 * 1024 * 1024)
        status_meta = next(t for t in tools if t["name"] == "sovereign_dual_modality_status")["_meta"]
        self.assertEqual(status_meta["ui"]["resourceUri"], "ui://alpha-mcp/workbench.html")
        self.assertEqual(
            [e["type"] for e in status_meta["com.google.antigravity/ui"]["entrypoints"]],
            ["aux_pane", "global"],
        )
        struct_resp = self._rpc("tools/call", {"name": "sovereign_dual_modality_status", "arguments": {}})["result"]
        self.assertEqual(struct_resp["structuredContent"], json.loads(struct_resp["content"][0]["text"]))
        for uri in ("alpha://genesis/anchor-t0", "alpha://hosting/zero-cost-blueprint", "alpha://telemetry/exodia-ledger"):
            rr = self._rpc("resources/read", {"uri": uri})
            self.assertIn("result", rr)
            parsed = json.loads(rr["result"]["contents"][0]["text"])
            self.assertIsInstance(parsed, dict)

        # 5. stage0_ast_slice_and_parity: .env airlock + SHA256_PARITY_HIT
        with tempfile.TemporaryDirectory() as td:
            env_path = Path(td) / ".env"
            env_path.write_text("SECRET_TOKEN=not-allowed\n", encoding="utf-8")
            denied, is_err, _ = self._tool_call("stage0_ast_slice_and_parity", {"filepath": str(env_path)})
            self.assertTrue(is_err)
            self.assertEqual(denied["code"], "SECRET_PATH_AIRLOCK_DENY")

            sample = Path(td) / "sample.py"
            sample.write_text("def hello() -> str:\n    return 'world'\n", encoding="utf-8")
            s1, err1, _ = self._tool_call("stage0_ast_slice_and_parity", {"filepath": str(sample), "end_line": 10})
            s2, err2, _ = self._tool_call("stage0_ast_slice_and_parity", {"filepath": str(sample), "end_line": 10})
            self.assertFalse(err1)
            self.assertFalse(err2)
            self.assertEqual(s1["status"], "SLICE_FETCHED")
            self.assertEqual(s2["status"], "SHA256_PARITY_HIT")
            self.assertEqual(s1["sha256"], s2["sha256"])

        # 6. apex_contactor_route_packet & vertex_keyless_query Flash Shunt
        routed, is_err, _ = self._tool_call(
            "apex_contactor_route_packet",
            {"requested_model": "gemini-3.5-flash", "objective": "Evaluate architecture"},
        )
        self.assertFalse(is_err)
        self.assertTrue(routed["shunt_applied"])
        self.assertEqual(routed["resolved_model"], "gemini-4-neon")
        self.assertEqual(len(routed["packet_sha256"]), 16)

        routed_big, _, _ = self._tool_call(
            "apex_contactor_route_packet",
            {"requested_model": "claude-3-haiku", "objective": "X" * 30000, "provider": "anthropic"},
        )
        self.assertEqual(routed_big["resolved_model"], "claude-opus-5-5")
        self.assertTrue(routed_big["truncated"])
        self.assertLessEqual(routed_big["estimated_tokens"], 6000)

        vtx, _, _ = self._tool_call("vertex_keyless_query", {"prompt": "ping", "model": "gemini-2.5-flash-lite"})
        self.assertEqual(vtx["resolved_model"], "gemini-4-neon")
        self.assertTrue(vtx["shunt_applied"])

        # 7. tandem_edge_route multi_turn escalation
        edge_mt, _, _ = self._tool_call("tandem_edge_route", {"phone_temp_c": 34.0, "vram_used_gb": 3.0, "multi_turn": True})
        self.assertEqual(edge_mt["resolved_model"], "gemini-4-neon")

        # 8. exodia_compaction_gate 25:1 & 15-turn receipt
        exodia, is_err, _ = self._tool_call("exodia_compaction_gate", {"cache_reads": 50, "cache_writes": 2, "turns": 15})
        self.assertFalse(is_err)
        self.assertTrue(exodia["compact_required"])
        self.assertEqual(exodia["taint_provenance"], "TAINT_0_ARCHITECT")
        self.assertIn("TAINT_0_ARCHITECT", exodia["DELTA_LINE_2"])

        # 9. interpolate_state_sheet: -32602 fault pointer (<120 tok) + CSAA artifact minting
        fault_obj, is_err, fault_raw = self._tool_call("interpolate_state_sheet", {})
        self.assertTrue(is_err)
        self.assertEqual(fault_obj["status"], "ERROR")
        self.assertEqual(fault_obj["code"], -32602)
        self.assertEqual(fault_obj["skill_uri"], "skill://alpha/state-interpolation/SKILL.md")
        self.assertEqual(len(fault_obj["sha256"]), 64)
        self.assertLess(len(fault_raw) // 4, 120)

        csaa, is_err, _ = self._tool_call(
            "interpolate_state_sheet",
            {
                "workflow_id": "wf-e2e-stdio-01",
                "act_open": {"step": "init"},
                "act_mid": {"step": "verify"},
                "act_exit": {"step": "seal"},
                "mechanical_assertions": {"parity_ok": True, "airlock_ok": True},
            },
        )
        self.assertFalse(is_err)
        self.assertEqual(csaa["state"], "completed")
        self.assertEqual(csaa["taintProvenance"], "VERIFIED_ARCHITECT")
        self.assertEqual(csaa["artifact"]["state"], "completed")
        self.assertEqual(csaa["artifact"]["signatureAlg"], "HMAC-SHA256")
        self.assertEqual(len(csaa["artifact"]["signature"]), 64)

        # 10. sovereign_dual_modality_status
        st, is_err, _ = self._tool_call("sovereign_dual_modality_status", {})
        self.assertFalse(is_err)
        self.assertEqual(st["version"], "2.0.0")
        self.assertEqual(st["transports"], ["stdio", "http"])
        self.assertEqual(st["pinned_tool_order"], expected_order)
        self.assertEqual(len(st["sep2640_skills"]), 3)
        self.assertEqual(len(st["a2a_agent_card_signature"]), 16)
        self.assertEqual(st["redaction_patterns_count"], 13)
        self.assertTrue(st["secret_path_airlock"])
        self.assertEqual(st["keyless_gcp"]["static_key_files_on_disk"], 0)
        self.assertEqual(
            st["zero_cost_online_tiers"],
            ["cloudflare_named_tunnel_$0", "cloud_run_min_scale_0_$0", "static_edge_pages_$0"],
        )

        # 11. 13-pattern redaction probe (all synthetic tokens constructed at runtime)
        probes = [
            "Bearer " + "SyntheticTokenXYZ987",
            "sntrys_" + "S" * 24,
            "AI" + "za" + "G" * 24,
            "ya29." + "O" * 24,
            "GOCSPX-" + "DummySecret123456",
            "sk-ant-" + "A" * 24,
            "sk-proj-" + "P" * 24,
            "ghp_" + "H" * 24,
            "AKIA" + "9" * 16,
            "xoxb-" + "123456789098",
            "sk_live_" + "L" * 20,
            "-----BEGIN " + "PRIVATE KEY-----",
            "MY_API_KEY=" + "RawPasswordValue999",
        ]
        red_res, is_err, red_text = self._tool_call("precompensate_stdout_delta", {"raw_stdout": "\n".join(probes)})
        self.assertFalse(is_err)
        self.assertEqual(red_res["status"], "PASSTHROUGH_CLEAN")
        for leaked in (
            "SyntheticTokenXYZ987",
            "S" * 24,
            "G" * 24,
            "O" * 24,
            "DummySecret123456",
            "A" * 24,
            "P" * 24,
            "H" * 24,
            "AKIA" + "9" * 16,
            "123456789098",
            "L" * 20,
            "RawPasswordValue999",
        ):
            self.assertNotIn(leaked, red_text)
        self.assertIn("[REDACTED:PRIVATE_KEY]", red_text)


class TestStreamableHTTPAndOAuthE2E(unittest.TestCase):
    """Runs real ThreadedHTTPServer (--require-auth) in a background thread."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._old_bearer = os.environ.get("ALPHA_MCP_BEARER_TOKEN")
        cls._old_oauth = os.environ.get("ALPHA_MCP_OAUTH_SECRET")
        cls.bearer_token = "e2e-bearer-" + secrets.token_hex(12)
        cls.oauth_secret = "e2e-oauth-" + secrets.token_hex(12)
        os.environ["ALPHA_MCP_BEARER_TOKEN"] = cls.bearer_token
        os.environ["ALPHA_MCP_OAUTH_SECRET"] = cls.oauth_secret

        cls.port = _free_port()
        cls.server = srv_mod.create_http_server("127.0.0.1", cls.port, require_auth=True, quiet=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        if cls._old_bearer is None:
            os.environ.pop("ALPHA_MCP_BEARER_TOKEN", None)
        else:
            os.environ["ALPHA_MCP_BEARER_TOKEN"] = cls._old_bearer
        if cls._old_oauth is None:
            os.environ.pop("ALPHA_MCP_OAUTH_SECRET", None)
        else:
            os.environ["ALPHA_MCP_OAUTH_SECRET"] = cls._old_oauth

    def _status_rpc_body(self) -> bytes:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": {"name": "sovereign_dual_modality_status", "arguments": {}},
            }
        ).encode("utf-8")

    def test_public_discovery_and_method_gates(self) -> None:
        st, _, body = _http_call(f"{self.base}/health")
        self.assertEqual(st, 200)
        health = json.loads(body)
        self.assertEqual(health["status"], "ONLINE")
        self.assertEqual(health["server"], "alpha-mcp")
        self.assertEqual(health["version"], "2.0.0")
        self.assertEqual(health["tools_count"], 10)
        self.assertTrue(health["flash_shunt_engaged"])

        st, _, body = _http_call(f"{self.base}/.well-known/agent-card.json")
        self.assertEqual(st, 200)
        card = json.loads(body)
        self.assertEqual(card["protocolVersion"], "1.0.1")
        self.assertEqual(card["signature"]["alg"], "HS256-SOVEREIGN")
        self.assertEqual(len(card["signature"]["prefix"]), 16)
        self.assertEqual(len(card["tools"]), 10)
        self.assertEqual(len(card["skills"]), 3)

        st, _, body = _http_call(f"{self.base}/equations")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["count"], 19)

        st, _, body = _http_call(f"{self.base}/skills")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["count"], 3)

        st, _, body = _http_call(f"{self.base}/.well-known/oauth-authorization-server")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["code_challenge_methods_supported"], ["S256"])

        st, _, body = _http_call(f"{self.base}/.well-known/oauth-protected-resource")
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["resource"].endswith("/mcp"))

        st, hdrs, _ = _http_call(f"{self.base}/mcp", method="GET")
        self.assertEqual(st, 405)
        self.assertIn("POST", hdrs.get("Allow", ""))

        st, hdrs, _ = _http_call(f"{self.base}/mcp", method="OPTIONS")
        self.assertEqual(st, 204)
        self.assertEqual(hdrs.get("Access-Control-Allow-Origin"), "*")

    def test_bearer_auth_and_unauthenticated_401(self) -> None:
        st, hdrs, body = _http_call(
            f"{self.base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=self._status_rpc_body(),
        )
        self.assertEqual(st, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")
        self.assertIn("/.well-known/oauth-protected-resource", hdrs.get("WWW-Authenticate", ""))

        st, hdrs, body = _http_call(
            f"{self.base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.bearer_token}"},
            body=self._status_rpc_body(),
        )
        self.assertEqual(st, 200)
        self.assertTrue(hdrs.get("Mcp-Session-Id"))
        self.assertIn(hdrs.get("MCP-Protocol-Version"), srv_mod.SUPPORTED_PROTOCOL_VERSIONS)
        payload = json.loads(json.loads(body)["result"]["content"][0]["text"])
        self.assertEqual(payload["version"], "2.0.0")
        self.assertEqual(len(payload["pinned_tool_order"]), 10)

        # DELETE /mcp session cleanup with Bearer
        st, _, body = _http_call(
            f"{self.base}/mcp",
            method="DELETE",
            headers={"Authorization": f"Bearer {self.bearer_token}", "Mcp-Session-Id": hdrs["Mcp-Session-Id"]},
        )
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["status"], "SESSION_CLOSED")

    def test_oauth_pkce_s256_replay_rotation_and_revocation(self) -> None:
        verifier = "e2e-pkce-verifier-" + secrets.token_hex(24)
        challenge = _pkce_s256(verifier)

        # Unauthenticated /oauth/authorize -> 403
        st, _, body = _http_call(
            f"{self.base}/oauth/authorize?client_id=test-client&code_challenge={challenge}&code_challenge_method=S256"
        )
        self.assertEqual(st, 403)
        self.assertEqual(json.loads(body)["error"], "access_denied")

        # Invalid /oauth/register metadata (missing or unsafe redirect_uris) -> 400
        st, _, body = _http_call(
            f"{self.base}/oauth/register",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"client_name": "rogue"}).encode("utf-8"),
        )
        self.assertEqual(st, 400)
        self.assertEqual(json.loads(body)["error"], "invalid_client_metadata")

        st, _, body = _http_call(
            f"{self.base}/oauth/register",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"client_name": "rogue-js", "redirect_uris": ["javascript:alert(1)"]}).encode("utf-8"),
        )
        self.assertEqual(st, 400)
        self.assertEqual(json.loads(body)["error"], "invalid_client_metadata")

        # Valid RFC 7591 /oauth/register -> 201
        st, _, body = _http_call(
            f"{self.base}/oauth/register",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"client_name": "e2e-suite", "redirect_uris": ["http://localhost/cb"]}).encode("utf-8"),
        )
        self.assertEqual(st, 201)
        client_id = json.loads(body)["client_id"]

        # Authenticated /oauth/authorize -> 302 redirect (and code in Location)
        st, hdrs, body = _http_call(
            f"{self.base}/oauth/authorize?"
            + urllib.parse.urlencode(
                {
                    "client_id": client_id,
                    "redirect_uri": "http://localhost/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "st-42",
                }
            ),
            headers={"X-Alpha-OAuth-Secret": self.oauth_secret},
            follow_redirects=False,
        )
        self.assertEqual(st, 302)
        loc = urllib.parse.urlsplit(hdrs["Location"])
        qs = urllib.parse.parse_qs(loc.query)
        self.assertEqual(qs["state"][0], "st-42")
        code = qs["code"][0]

        # Exchange code + PKCE verifier -> 200 access_token + refresh_token
        token_form = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "client_id": client_id,
                "redirect_uri": "http://localhost/cb",
            }
        ).encode("utf-8")
        st, _, body = _http_call(
            f"{self.base}/oauth/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=token_form,
        )
        self.assertEqual(st, 200)
        tok = json.loads(body)
        access_token = tok["access_token"]
        refresh_token = tok["refresh_token"]

        # Call POST /mcp using OAuth access_token -> 200
        st, _, body = _http_call(
            f"{self.base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {access_token}"},
            body=self._status_rpc_body(),
        )
        self.assertEqual(st, 200)
        self.assertFalse(json.loads(body)["result"]["isError"])

        # Replay same authorization code -> 400 invalid_grant
        st, _, body = _http_call(
            f"{self.base}/oauth/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=token_form,
        )
        self.assertEqual(st, 400)
        self.assertEqual(json.loads(body)["error"], "invalid_grant")

        # Refresh token rotation -> new access_token works, old invalidated
        rot_form = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": refresh_token}).encode("utf-8")
        st, _, body = _http_call(
            f"{self.base}/oauth/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=rot_form,
        )
        self.assertEqual(st, 200)
        new_access = json.loads(body)["access_token"]
        self.assertNotEqual(new_access, access_token)

        st, _, _ = _http_call(
            f"{self.base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {access_token}"},
            body=self._status_rpc_body(),
        )
        self.assertEqual(st, 401)

        st, _, _ = _http_call(
            f"{self.base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {new_access}"},
            body=self._status_rpc_body(),
        )
        self.assertEqual(st, 200)

        # Revoke active token via RFC 7009 -> subsequent POST /mcp returns 401
        rev_form = urllib.parse.urlencode({"token": new_access}).encode("utf-8")
        st, _, _ = _http_call(
            f"{self.base}/oauth/revoke",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=rev_form,
        )
        self.assertEqual(st, 200)

        st, _, _ = _http_call(
            f"{self.base}/mcp",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {new_access}"},
            body=self._status_rpc_body(),
        )
        self.assertEqual(st, 401)

    def test_gemini_openauth_dcr_consent_and_cold_start_tokens(self) -> None:
        # 1. HEAD /mcp -> 401 with WWW-Authenticate and HEAD /health -> 200 (never 501)
        st, hdrs, _ = _http_call(f"{self.base}/mcp", method="HEAD")
        self.assertEqual(st, 401)
        self.assertIn("/.well-known/oauth-protected-resource", hdrs.get("WWW-Authenticate", ""))
        st, _, _ = _http_call(f"{self.base}/health", method="HEAD")
        self.assertEqual(st, 200)

        # 2. RFC 7591 unauthenticated DCR with client_secret_basic -> 201
        redirect_uri = "https://gemini.google.com/oauth/callback"
        st, _, body = _http_call(
            f"{self.base}/oauth/register",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {
                    "client_name": "Gemini OpenAuth",
                    "redirect_uris": [redirect_uri],
                    "token_endpoint_auth_method": "client_secret_basic",
                }
            ).encode("utf-8"),
        )
        self.assertEqual(st, 201)
        reg = json.loads(body)
        cid = reg["client_id"]
        csec = reg["client_secret"]
        self.assertTrue(cid.startswith("alpha-client-"))
        self.assertTrue(csec.startswith("amcp_cs_"))

        # 3. Browser GET /oauth/authorize with 2,500-char state -> 200 HTML consent page
        verifier = "openauth-pkce-verifier-" + secrets.token_hex(24)
        challenge = _pkce_s256(verifier)
        long_state = "s" * 2500
        auth_qs = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp:read mcp:tools",
                "state": long_state,
            }
        )
        st, hdrs, body = _http_call(
            f"{self.base}/oauth/authorize?{auth_qs}",
            headers={"Accept": "text/html"},
        )
        self.assertEqual(st, 200)
        self.assertIn("text/html", hdrs.get("Content-Type", ""))
        csp = hdrs.get("Content-Security-Policy", "")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("form-action", csp)
        self.assertIn("Authorize Alpha MCP Access", body)

        base_form = {
            "consent_ui": "1",
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:read mcp:tools",
            "state": long_state,
        }

        # 4. Browser POST /oauth/authorize with wrong secret -> 403 HTML
        st, hdrs, body = _http_call(
            f"{self.base}/oauth/authorize",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"},
            body=urllib.parse.urlencode({**base_form, "oauth_secret": "wrong-secret", "decision": "approve"}).encode("utf-8"),
        )
        self.assertEqual(st, 403)
        self.assertIn("text/html", hdrs.get("Content-Type", ""))

        # 5. Browser POST /oauth/authorize decision=deny -> 302 with error=access_denied and exact state
        st, hdrs, _ = _http_call(
            f"{self.base}/oauth/authorize",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"},
            body=urllib.parse.urlencode({**base_form, "decision": "deny"}).encode("utf-8"),
            follow_redirects=False,
        )
        self.assertEqual(st, 302)
        deny_qs = urllib.parse.parse_qs(urllib.parse.urlsplit(hdrs["Location"]).query)
        self.assertEqual(deny_qs["error"][0], "access_denied")
        self.assertEqual(deny_qs["state"][0], long_state)

        # 6. Browser POST /oauth/authorize with bearer_token -> 302 with code and exact 2,500-char state
        st, hdrs, _ = _http_call(
            f"{self.base}/oauth/authorize",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"},
            body=urllib.parse.urlencode({**base_form, "oauth_secret": self.bearer_token, "decision": "approve"}).encode("utf-8"),
            follow_redirects=False,
        )
        self.assertEqual(st, 302)
        ok_qs = urllib.parse.parse_qs(urllib.parse.urlsplit(hdrs["Location"]).query)
        self.assertEqual(ok_qs["state"][0], long_state)
        code = ok_qs["code"][0]
        self.assertTrue(code.startswith("amcp_ac."))

        # 7. POST /oauth/token with Authorization: Basic + PKCE code_verifier -> 200 amcp_at. + amcp_rt.
        basic_raw = f"{urllib.parse.quote_plus(cid)}:{urllib.parse.quote_plus(csec)}".encode("utf-8")
        basic_hdr = "Basic " + base64.b64encode(basic_raw).decode("ascii")
        st, _, body = _http_call(
            f"{self.base}/oauth/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic_hdr},
            body=urllib.parse.urlencode(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": redirect_uri,
                }
            ).encode("utf-8"),
        )
        self.assertEqual(st, 200)
        tok = json.loads(body)
        access_token = tok["access_token"]
        refresh_token = tok["refresh_token"]
        self.assertTrue(access_token.startswith("amcp_at."))
        self.assertTrue(refresh_token.startswith("amcp_rt."))

        # 8. Cold-start verification: fresh OAuthPKCEBroker instance validates & rotates stateless tokens
        fresh_broker = srv_mod.OAuthPKCEBroker()
        self.assertTrue(fresh_broker.validate_access_token(access_token))
        rotated, rot_err = fresh_broker.rotate_refresh_token(refresh_token, client_id=cid, client_secret=csec)
        self.assertIsNone(rot_err)
        self.assertIsNotNone(rotated)
        assert rotated is not None
        self.assertTrue(fresh_broker.validate_access_token(rotated["access_token"]))

    def test_google_signin_oauth_bridge_allowlist_and_csrf(self) -> None:
        old_env = {k: os.environ.get(k) for k in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "ALPHA_MCP_ALLOWED_EMAILS")}
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "test-google-client.apps.googleusercontent.com"
        os.environ["GOOGLE_OAUTH_CLIENT_SECRET"] = "test-google-client-secret"
        os.environ["ALPHA_MCP_ALLOWED_EMAILS"] = "eloquent@eloquentwin.com"
        try:
            # 1. /health reports oauth_login_mode=google_signin
            st, _, body = _http_call(f"{self.base}/health")
            self.assertEqual(st, 200)
            self.assertEqual(json.loads(body)["oauth_login_mode"], "google_signin")

            # 2. Register DCR client
            redirect_uri = "https://oauth-redirect.googleusercontent.com/r/gemini-test"
            st, _, body = _http_call(
                f"{self.base}/oauth/register",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"client_name": "Gemini", "redirect_uris": [redirect_uri]}).encode("utf-8"),
            )
            self.assertEqual(st, 201)
            cid = json.loads(body)["client_id"]

            # 3. GET /oauth/authorize -> 302 to accounts.google.com + Set-Cookie alpha_oauth_csrf
            verifier = "google-bridge-pkce-" + secrets.token_hex(24)
            challenge = _pkce_s256(verifier)
            auth_qs = urllib.parse.urlencode(
                {
                    "response_type": "code",
                    "client_id": cid,
                    "redirect_uri": redirect_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "scope": "mcp:read mcp:tools",
                    "state": "gemini-state-999",
                }
            )
            st, hdrs, _ = _http_call(
                f"{self.base}/oauth/authorize?{auth_qs}",
                headers={"Accept": "text/html"},
                follow_redirects=False,
            )
            self.assertEqual(st, 302)
            loc = hdrs["Location"]
            self.assertTrue(loc.startswith("https://accounts.google.com/o/oauth2/v2/auth"))
            g_qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
            gstate = g_qs["state"][0]
            self.assertTrue(gstate.startswith("amcp_gs."))
            cookie_hdr = hdrs.get("Set-Cookie", "")
            self.assertIn("alpha_oauth_csrf=", cookie_hdr)
            csrf_pair = cookie_hdr.split(";", 1)[0]

            # 4. Callback without CSRF cookie -> 403
            st, _, _ = _http_call(
                f"{self.base}/oauth/google/callback?" + urllib.parse.urlencode({"state": gstate, "code": "gcode-1"}),
                follow_redirects=False,
            )
            self.assertEqual(st, 403)

            # 5. Callback with non-allowlisted email -> 403
            with mock.patch.object(
                srv_mod,
                "_exchange_google_code_for_userinfo",
                return_value=({"email": "stranger@example.com", "email_verified": True}, None),
            ):
                st, _, _ = _http_call(
                    f"{self.base}/oauth/google/callback?" + urllib.parse.urlencode({"state": gstate, "code": "gcode-2"}),
                    headers={"Cookie": csrf_pair},
                    follow_redirects=False,
                )
                self.assertEqual(st, 403)

            # 6. Callback with unverified allowlisted email -> 403
            with mock.patch.object(
                srv_mod,
                "_exchange_google_code_for_userinfo",
                return_value=({"email": "eloquent@eloquentwin.com", "email_verified": False}, None),
            ):
                st, _, _ = _http_call(
                    f"{self.base}/oauth/google/callback?" + urllib.parse.urlencode({"state": gstate, "code": "gcode-3"}),
                    headers={"Cookie": csrf_pair},
                    follow_redirects=False,
                )
                self.assertEqual(st, 403)

            # 7. Callback with allowlisted verified email -> 302 to Gemini redirect_uri + PKCE token exchange
            with mock.patch.object(
                srv_mod,
                "_exchange_google_code_for_userinfo",
                return_value=({"email": "eloquent@eloquentwin.com", "email_verified": True}, None),
            ):
                st, hdrs, _ = _http_call(
                    f"{self.base}/oauth/google/callback?" + urllib.parse.urlencode({"state": gstate, "code": "gcode-4"}),
                    headers={"Cookie": csrf_pair},
                    follow_redirects=False,
                )
                self.assertEqual(st, 302)
                cb_qs = urllib.parse.parse_qs(urllib.parse.urlsplit(hdrs["Location"]).query)
                self.assertEqual(cb_qs["state"][0], "gemini-state-999")
                mcp_code = cb_qs["code"][0]
                self.assertTrue(mcp_code.startswith("amcp_ac."))

            st, _, body = _http_call(
                f"{self.base}/oauth/token",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=urllib.parse.urlencode(
                    {
                        "grant_type": "authorization_code",
                        "code": mcp_code,
                        "code_verifier": verifier,
                        "client_id": cid,
                        "redirect_uri": redirect_uri,
                    }
                ).encode("utf-8"),
            )
            self.assertEqual(st, 200)
            tok = json.loads(body)
            self.assertTrue(tok["access_token"].startswith("amcp_at."))
            self.assertTrue(tok["refresh_token"].startswith("amcp_rt."))
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_non_loopback_forwarded_header_fail_closed(self) -> None:
        port = _free_port()
        srv = srv_mod.create_http_server("127.0.0.1", port, require_auth=False, quiet=True)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            url = f"http://127.0.0.1:{port}/mcp"
            # Plain loopback without --require-auth succeeds
            st, _, _ = _http_call(url, method="POST", headers={"Content-Type": "application/json"}, body=self._status_rpc_body())
            self.assertEqual(st, 200)
            # Remote forwarding header triggers fail-closed 401
            st, _, _ = _http_call(
                url,
                method="POST",
                headers={"Content-Type": "application/json", "X-Forwarded-Host": "mcp.example.com"},
                body=self._status_rpc_body(),
            )
            self.assertEqual(st, 401)
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(timeout=3)


class TestCarbonIngestV21(unittest.TestCase):
    def test_idempotent_reingest_secret_airlock_and_telemetry(self) -> None:
        import mcp_carbon_ingest as ingest_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sample_repo"
            root.mkdir(parents=True)
            (root / "app.py").write_text("def hello(name):\n    return f'hi {name}'\n", encoding="utf-8")
            (root / "page.html").write_text(
                "<html><body><h1>Portal</h1><a href='https://example.org/docs'>Docs</a></body></html>\n",
                encoding="utf-8",
            )
            (root / ".env").write_text("SERVICE_TOKEN=super_secret_token_value_123456\n", encoding="utf-8")
            (root / "notes.md").write_text("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.payload\n", encoding="utf-8")
            db_path = Path(tmp) / "vault.sqlite3"

            for _ in range(2):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(REPO_ROOT / "mcp_carbon_ingest.py"),
                        "ingest",
                        "--roots",
                        str(root),
                        "--db",
                        str(db_path),
                        "--workers",
                        "1",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                self.assertIn("[ROOT_GAUGE]", proc.stdout)

            conn = ingest_mod.sqlite3.connect(str(db_path))
            try:
                files = conn.execute("SELECT path, ast_summary, is_duplicate FROM files ORDER BY path").fetchall()
                dup_flags = {Path(p).name: dup for p, _, dup in files}
                self.assertEqual(dup_flags["app.py"], 0)
                self.assertEqual(dup_flags["page.html"], 0)
                self.assertEqual(dup_flags[".env"], 0)
                self.assertEqual(dup_flags["notes.md"], 0)
                asts = {Path(p).name: a for p, a, _ in files}
                self.assertEqual(asts[".env"], "[SECRET_PATH_AIRLOCK_SKIPPED]")

                slices = conn.execute("SELECT path, content FROM slices_fts").fetchall()
                slice_names = [Path(p).name for p, _ in slices]
                self.assertEqual(slice_names.count("app.py"), 1)
                self.assertEqual(slice_names.count("page.html"), 1)
                self.assertEqual(slice_names.count(".env"), 0)
                joined_content = "\n".join(c for _, c in slices)
                self.assertNotIn("super_secret_token_value", joined_content)
                self.assertNotIn("eyJhbGci", joined_content)

                audit_types = {r[0] for r in conn.execute("SELECT secret_type FROM secret_audit").fetchall()}
                self.assertIn("SECRET_PATH_SKIPPED", audit_types)
                self.assertIn("BEARER_TOKEN", audit_types)

                telem = conn.execute(
                    "SELECT folder_root, candidate_files, indexed_files, coverage_pct, mb_per_sec FROM ingest_telemetry"
                ).fetchall()
                self.assertEqual(len(telem), 2)
                self.assertEqual(telem[-1][0], "sample_repo")
                self.assertEqual(telem[-1][1], 4)
                self.assertEqual(telem[-1][2], 4)
                self.assertEqual(telem[-1][3], 100.0)
                self.assertGreater(telem[-1][4], 0.0)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
