---
name: alpha-mcp
description: >-
  Run the zero-dependency Alpha MCP Stage 0 local research vault (mcp_carbon_ingest.py):
  SHA-256 deduplication, 3-mode safe VHDX/ZIP inspection, native Jupyter .ipynb cleaning,
  160-line AST slicing, pre-share credential redaction audit, BM25 FTS5 search, and the
  interactive walk-along guide. Use when indexing local repositories, auditing secrets
  before a Git push, or querying a local SQLite FTS5 research vault for MCP workflows.
metadata:
  icon: bolt
  logo: logo.svg
---

# Alpha MCP — Stage 0 Local Research Vault & Inference Bridge

Use this skill to index heterogeneous codebases, notebooks, shortcuts, `.zip` archives, and `.vhdx` virtual disks into a fast, local SQLite WAL + BM25 FTS5 vault with automatic credential redaction and zero pip dependencies.

## Quick Start (60 Seconds)

1. **Test on the bundled sample workspace:**
   ```bash
   python mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db ./sample_vault.sqlite3 --vhdx-mode inspect
   python mcp_carbon_ingest.py audit --db ./sample_vault.sqlite3
   python mcp_carbon_ingest.py query "mcp" --db ./sample_vault.sqlite3 --top 5
   ```
2. **Index real local folders safely (`--vhdx-mode inspect` never unpacks multi-GB disk images):**
   ```bash
   python mcp_carbon_ingest.py ingest --roots ./folder-a ./folder-b --db ./mcp_alpha_vault.sqlite3 --vhdx-mode inspect
   ```
3. **Interactive Walk-Along & Full Tutorial:**
   - Interactive 4-step simulator: [walk-along/index.html](../../walk-along/index.html)
   - Enriched tutorial, best practices, BM25 cookbook & possibilities: [USER_TUTORIAL_GUIDE.md](../../USER_TUTORIAL_GUIDE.md)
   - Unified inference layer & tail-pinned MCP slots: [INFERENCE_LAYER_SPEC.md](../../INFERENCE_LAYER_SPEC.md)

## Guardrails
- Always run `audit` before sharing any raw indexed folder externally; keep `*.sqlite3*`, `.vhdx`, `.pdf`, `.zip`, and `.pkl` out of Git via `.gitignore`.
- Never unpack full `.vhdx` images unless `audit` / `vhdx_manifest` proves user source files exist inside them; use `--vhdx-mode selective-extract` only when justified.

## Live MCP Server Tools (`alpha_mcp_server.py`, stdio)

Mount with `python alpha_mcp_server.py --transport stdio` (set `ALPHA_MCP_VAULT_DB` to your vault). Six read-only tools:

- `stage0_vault_fts_query` - BM25 FTS5 search over the redacted vault.
- `stage0_vault_manifest_lookup` - counts plus VHDX/ZIP/link/secret-audit manifests (metadata only).
- `stage0_ast_slice_and_parity` - <=160-line slices with SHA-256 dedup; blocks `.env`, keys, OAuth JSON.
- `precompensate_stdout_delta` - compresses noisy logs into a fault-only delta.
- `tandem_edge_route` - thermal (32-42C quintic ramp) and VRAM headroom router.
- `vertex_keyless_query` - optional Vertex AI call via keyless service-account impersonation.

Cloud export (optional, keyless REST): `python mcp_carbon_ingest.py sync --target gcp --bucket <bucket> --impersonate-sa <worker>@<project>.iam.gserviceaccount.com --apply`.
