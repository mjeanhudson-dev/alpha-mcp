#!/usr/bin/env python3
"""Minimal stdlib-only MCP research server fixture for Stage 0 AST & FTS5 indexing demos."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class VaultConfig:
    """Configuration contract for a local SQLite WAL + FTS5 research vault."""

    db_path: Path
    max_slice_lines: int = 160
    default_top_k: int = 8

    def resolved_db(self) -> Path:
        return self.db_path.expanduser().resolve()


class LocalResearchMCPServer:
    """Read-only MCP tool router exposing deterministic BM25 slice search."""

    def __init__(self, config: VaultConfig) -> None:
        self.config = config

    def list_tools(self) -> list[dict[str, Any]]:
        """Returns prefix-pinned tool schemas for MCP clients."""
        return [
            {
                "name": "stage0_vault_fts_query",
                "description": "Run a BM25 FTS5 query across scrubbed <=160-line research slices.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "top_k": {"type": "integer", "default": self.config.default_top_k},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "stage0_vault_manifest_lookup",
                "description": "Inspect indexed files, archive manifests, and redaction counts.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def query_slices(self, search_query: str, top_k: int | None = None) -> list[dict[str, Any]]:
        """Executes a read-only BM25 query against slices_fts."""
        limit = top_k or self.config.default_top_k
        uri = f"file:{self.config.resolved_db().as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            rows = conn.execute(
                """SELECT path, line_range, ast_summary,
                          snippet(slices_fts, 5, '>>>', '<<<', ' ... ', 24)
                   FROM slices_fts
                   WHERE slices_fts MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (search_query, limit),
            ).fetchall()
        return [
            {
                "path": row[0],
                "line_range": row[1],
                "ast_summary": row[2],
                "snippet": row[3],
            }
            for row in rows
        ]

    def handle_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Dispatches minimal JSON-RPC 2.0 MCP method calls."""
        method = payload.get("method", "")
        req_id = payload.get("id")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}
        if method == "tools/call":
            params = payload.get("params", {})
            if params.get("name") == "stage0_vault_fts_query":
                args = params.get("arguments", {})
                hits = self.query_slices(args.get("query", "mcp"), args.get("top_k"))
                return {"jsonrpc": "2.0", "id": req_id, "result": {"hits": hits}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}


def format_receipt(files: int, slices: int, links: int, secrets: int) -> str:
    """Formats a compact Stage 0 telemetry receipt line."""
    return json.dumps(
        {
            "files": files,
            "slices_160L": slices,
            "links": links,
            "secrets_redacted": secrets,
        },
        sort_keys=True,
    )


def main() -> None:
    server = LocalResearchMCPServer(VaultConfig(db_path=Path("./mcp_alpha_vault.sqlite3")))
    print(json.dumps({"tools": [t["name"] for t in server.list_tools()]}))


if __name__ == "__main__":
    main()
