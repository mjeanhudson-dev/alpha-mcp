#!/usr/bin/env python3
"""Sanitization, Air-Gap & Origin-Lock E2E tests for commercial_mcp_server.py."""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import commercial_mcp_server as srv_mod  # noqa: E402


def _req(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, dict[str, str], str]:
    r = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode("utf-8", "replace")
        finally:
            e.close()


class TestCommercialMCPSanitization(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._old_sec = os.environ.get("ELOQUENT_EDGE_SHARED_SECRET")
        cls._old_quiet = os.environ.get("COMMERCIAL_MCP_QUIET")
        cls.edge_secret = "edge-test-" + secrets.token_hex(16)
        os.environ["ELOQUENT_EDGE_SHARED_SECRET"] = cls.edge_secret
        os.environ["COMMERCIAL_MCP_QUIET"] = "1"
        cls.httpd = srv_mod.CommercialMCPServer(("127.0.0.1", 0), srv_mod.CommercialHandler)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        if cls._old_sec is None:
            os.environ.pop("ELOQUENT_EDGE_SHARED_SECRET", None)
        else:
            os.environ["ELOQUENT_EDGE_SHARED_SECRET"] = cls._old_sec
        if cls._old_quiet is None:
            os.environ.pop("COMMERCIAL_MCP_QUIET", None)
        else:
            os.environ["COMMERCIAL_MCP_QUIET"] = cls._old_quiet

    def _mcp(self, payload: dict, edge_secret: str | None = None, tier: str = "pro") -> tuple[int, dict]:
        hdrs = {"Content-Type": "application/json", "X-Eloquent-Tier": tier}
        if edge_secret is not None:
            hdrs["X-Eloquent-Edge-Secret"] = edge_secret
        st, _, body = _req(f"{self.base}/mcp", method="POST", headers=hdrs, body=json.dumps(payload).encode("utf-8"))
        return st, json.loads(body)

    def test_origin_lock_blocks_direct_requests(self) -> None:
        st, body = self._mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, edge_secret=None)
        self.assertEqual(st, 403)
        self.assertEqual(body["error"], "edge_gateway_required")

        st2, _ = self._mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, edge_secret="wrong-secret")
        self.assertEqual(st2, 403)

    def test_zero_owner_tools_and_zero_personal_leaks(self) -> None:
        st, body = self._mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, edge_secret=self.edge_secret)
        self.assertEqual(st, 200)
        names = [t["name"] for t in body["result"]["tools"]]
        self.assertEqual(len(names), 7)
        for forbidden in ("stage0_vault_fts_query", "stage0_vault_manifest_lookup", "stage0_ast_slice_and_parity", "vertex_keyless_query"):
            self.assertNotIn(forbidden, names)

        # Attempting to call a private owner tool fails closed with -32601
        st2, err_body = self._mcp(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "stage0_vault_fts_query", "arguments": {"query": "secret"}}},
            edge_secret=self.edge_secret,
        )
        self.assertEqual(st2, 200)
        self.assertEqual(err_body["error"]["code"], -32601)

    def test_inline_slicer_redacts_secrets_and_never_reads_disk(self) -> None:
        fake_elq = "elq_" + "live_" + ("0123456789abcdef" * 2)
        fake_stripe = "sk_" + "live_" + "abcdefgh1234567890"
        fake_code = (
            "def leak_test():\n"
            f"    k1 = '{fake_elq}'\n"
            f"    k2 = '{fake_stripe}'\n"
            "    p = r'C:\\Users\\Alice\\secrets.env'\n"
            "    return (k1, k2, p)\n"
        )
        st, body = self._mcp(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "stage0_ast_slice_inline", "arguments": {"source_code": fake_code, "language": "python"}}},
            edge_secret=self.edge_secret,
        )
        self.assertEqual(st, 200)
        sc = body["result"]["structuredContent"]
        self.assertEqual(sc["status"], "OK")
        self.assertEqual(sc["commercial_tier"], "pro")
        self.assertNotIn("0123456789abcdef0123456789abcdef", sc["content"])
        self.assertNotIn("sk_live_abcdefgh", sc["content"])
        self.assertNotIn("Alice", sc["content"])
        self.assertIn("[REDACTED:ELOQUENT_KEY]", sc["content"])
        self.assertIn("[REDACTED:STRIPE_KEY]", sc["content"])

    def test_health_and_workbench_resource(self) -> None:
        st, _, raw = _req(f"{self.base}/health")
        self.assertEqual(st, 200)
        h = json.loads(raw)
        self.assertTrue(h["zero_disk_vault"])
        self.assertTrue(h["runtime_parity_ok"])

        st2, body = self._mcp(
            {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "ui://eloquent-mcp/workbench.html"}},
            edge_secret=self.edge_secret,
        )
        self.assertEqual(st2, 200)
        html = body["result"]["contents"][0]["text"]
        self.assertIn("Eloquent Commercial MCP Workbench", html)


if __name__ == "__main__":
    unittest.main()
