---
name: alpha-mcp
description: >-
  Run the zero-dependency Alpha MCP v2.0 Stage 0 local research vault (mcp_carbon_ingest.py)
  and Sovereign Dual-Modality MCP server (alpha_mcp_server.py): stdio and authenticated
  Streamable HTTP, 10 prefix-pinned tools, OAuth 2.1 S256 PKCE, signed Google A2A v1.0.1,
  SEP-2640 atomic skills, SHA-256 deduplication, 3-mode safe VHDX/ZIP inspection, native
  Jupyter .ipynb cleaning, 160-line AST slicing, pre-share credential redaction audit,
  BM25 FTS5 search, and $0.00/mo online deployment (Cloudflare Named Tunnel and Cloud Run).
metadata:
  icon: bolt
  logo: logo.svg
---

# Alpha MCP v2.0 — Stage 0 Local Research Vault & Sovereign Dual-Modality MCP

Use this skill to index heterogeneous codebases, notebooks, shortcuts, `.zip` archives, and `.vhdx` virtual disks into a fast, local SQLite WAL + BM25 FTS5 vault with automatic credential redaction, and serve it over local `stdio` or `$0.00/mo` authenticated `Streamable HTTP` with zero pip dependencies.

## Quick Start (60 Seconds)

1. **Test on the bundled sample workspace:**
   ```bash
   # ==============================================================================
   # LABEL:               Alpha MCP Sample Workspace Ingest, Audit, and Query
   # USE:                 Verify Stage 0 indexing, credential redaction audit, and BM25 search against the bundled 6-file demo workspace.
   # MECHANISM_OF_ACTION: Runs mcp_carbon_ingest.py (Python 3.10+ stdlib) in inspect mode to build ./sample_vault.sqlite3, audit redacted hits, and run ranked FTS5 queries.
   # ==============================================================================
   python ./mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db ./sample_vault.sqlite3 --vhdx-mode inspect
   python ./mcp_carbon_ingest.py audit --db ./sample_vault.sqlite3
   python ./mcp_carbon_ingest.py query "mcp" --db ./sample_vault.sqlite3 --top 5
   ```
2. **Index real local folders safely (`--vhdx-mode inspect` never unpacks multi-GB disk images):**
   ```bash
   # ==============================================================================
   # LABEL:               Alpha MCP Multi-Root Local Vault Ingestion
   # USE:                 Build a local SQLite WAL + BM25 FTS5 vault across one or more local folders without unpacking virtual disks.
   # MECHANISM_OF_ACTION: Invokes mcp_carbon_ingest.py with --vhdx-mode inspect to stream mmap SHA-256 hashes, scrub 9 secret classes, extract Python AST summaries, and index <=160-line slices.
   # ==============================================================================
   python ./mcp_carbon_ingest.py ingest --roots ./folder-a ./folder-b --db ./mcp_alpha_vault.sqlite3 --vhdx-mode inspect
   ```
3. **Interactive Walk-Along, Zero-Cost Online Blueprint & Full Tutorial:**
   - Live Interactive Walk-Along (GitHub Pages): [https://mjeanhudson-dev.github.io/alpha-mcp/walk-along/](https://mjeanhudson-dev.github.io/alpha-mcp/walk-along/) (local: [walk-along/index.html](../../walk-along/index.html))
   - Zero-Cost Online Architecture (`$0.00/mo` Named Tunnel + Cloud Run + Edge): [deploy/ZERO_COST_ONLINE_ARCHITECTURE.md](../../deploy/ZERO_COST_ONLINE_ARCHITECTURE.md)
   - Enriched tutorial, best practices, BM25 cookbook & possibilities: [USER_TUTORIAL_GUIDE.md](../../USER_TUTORIAL_GUIDE.md)
   - Unified inference layer & tail-pinned MCP slots: [INFERENCE_LAYER_SPEC.md](../../INFERENCE_LAYER_SPEC.md)

## Sovereign Dual-Modality Server (`alpha_mcp_server.py` v2.0.0)

- **Local `stdio` (default for `plugin.json` / IDE configs):** `python ./alpha_mcp_server.py --transport stdio` (set `ALPHA_MCP_VAULT_DB` to your vault path).
- **Authenticated `Streamable HTTP` (`$0.00/mo` Cloudflare Named Tunnel or Cloud Run `min-instances=0`):**
  ```powershell
  # ==============================================================================
  # LABEL:               Launch Authenticated Dual-Modality HTTP Edge Server
  # USE:                 Expose Alpha MCP v2.0 over Streamable HTTP with fail-closed Bearer/OAuth 2.1 S256 PKCE enforcement and optional Cloudflare Named Tunnel binding.
  # MECHANISM_OF_ACTION: Sets required auth secrets in environment and executes deploy/Start-DualModalityEdge.ps1 to start --transport http --require-auth, poll /health until ONLINE, and attach cloudflared.
  # ==============================================================================
  $env:ALPHA_MCP_BEARER_TOKEN   = "<your-long-random-bearer-token>"
  $env:ALPHA_MCP_OAUTH_SECRET   = "<your-long-random-oauth-secret>"
  $env:ALPHA_MCP_SIGNING_SECRET = "<your-long-random-signing-secret>"
  ./deploy/Start-DualModalityEdge.ps1 -Port 8000 -TunnelName "<your-tunnel-name>" -VaultDb "./mcp_alpha_vault.sqlite3"
  ```

### 10 Prefix-Pinned Tools (`capabilities.tools.listChanged = false`)

1. `stage0_vault_fts_query` — BM25 FTS5 search over redacted `<=160`-line vault slices.
2. `stage0_vault_manifest_lookup` — Vault counts plus `vhdx`, `zip`, `links`, and `secret_audit` manifests (metadata only).
3. `stage0_ast_slice_and_parity` — `<=160`-line slices with SHA-256 dedup; blocks `.env`, `.pem`, `.key`, and OAuth JSON (`SECRET_PATH_AIRLOCK_DENY`).
4. `precompensate_stdout_delta` — Compresses noisy logs (`>500` tokens) into a `<300`-token fault-only delta.
5. `tandem_edge_route` — Thermal (`32-42C` quintic ramp) and `7.08` GB VRAM router with `multi_turn` escalation to `gemini-4-neon`.
6. `vertex_keyless_query` — Keyless Vertex AI call via `gcloud` SA impersonation (`0` static keys) with Apex shunt (`gemini-4-neon` default).
7. `apex_contactor_route_packet` — Across-the-Line Apex Contactor (`NEXUS_FLASH_SHUNT=1`): shunts Flash/Lite/Mini/Haiku/Nano tiers to frontier Apex models (`gemini-4-neon`, `claude-opus-5-5`, `gpt-5-pro-high`) with `<=6,000`-token packets and 16-hex `packet_sha256`.
8. `exodia_compaction_gate` — Evaluates `cache_reads / max(1, cache_writes)` vs `25:1` and turn threshold (`>=15`), emitting a 3-line taint-preserving SHA-256 delta (`TAINT_0_ARCHITECT`).
9. `interpolate_state_sheet` — SEP-2640 fault-pointer precheck (`-32602` pointing to `skill://alpha/state-interpolation/SKILL.md` if `workflow_id` missing) and HMAC-SHA256 signed CSAA A2A artifact minting.
10. `sovereign_dual_modality_status` — Returns v2.0.0 runtime telemetry, pinned 10-tool order, 3 SEP-2640 atomic skill manifests, signed A2A `v1.0.1` digest, 13-pattern redaction count, keyless GCP status, and `$0.00/mo` hosting tiers.

### Protocol, Auth & Discovery Surface

- **Signed Google A2A `v1.0.1`:** `GET /.well-known/agent-card.json` (`HS256-SOVEREIGN` HMAC via `ALPHA_MCP_SIGNING_SECRET` or per-boot `secrets.token_bytes(32)`).
- **OAuth 2.1 `S256` PKCE:** RFC 9728 `/.well-known/oauth-protected-resource`, RFC 8414 `/.well-known/oauth-authorization-server`, gated `/oauth/authorize` (`ALPHA_MCP_OAUTH_SECRET` or Bearer), single-use `/oauth/token` (`S256` + refresh rotation), and RFC 7009 `/oauth/revoke`.
- **Resources & Nil-Arg Prompts:** `alpha://genesis/anchor-t0`, `alpha://vault/manifest-summary`, `alpha://hosting/zero-cost-blueprint`, `alpha://telemetry/exodia-ledger`; prompts `kppc_lod_blueprint`, `exodia_zero_drag_audit`, `zero_cost_online_deploy`.

## Guardrails & Keyless Cloud Sync

- Always run `audit` before sharing any raw indexed folder externally; keep `*.sqlite3*`, `.vhdx`, `.pdf`, `.zip`, and `.pkl` out of Git and container builds via `.gitignore` and `.dockerignore`.
- Never unpack full `.vhdx` images unless `audit` / `vhdx_manifest` proves user source files exist inside them; use `--vhdx-mode selective-extract` only when justified.
- Never expose `--transport http` remotely without `--require-auth` and a non-empty `ALPHA_MCP_BEARER_TOKEN` (plus `ALPHA_MCP_OAUTH_SECRET` for OAuth authorization).

Optional keyless cloud export (redacted vault only, zero static key files):

```bash
# ==============================================================================
# LABEL:               Keyless GCP Vault Export (GCS + BigQuery)
# USE:                 Sync the scrubbed SQLite vault to Cloud Storage and BigQuery Always-Free tiers via short-lived SA impersonation.
# MECHANISM_OF_ACTION: Runs mcp_carbon_ingest.py sync --target gcp --apply over HTTPS REST after verifying zero unredacted credentials remain in the vault.
# ==============================================================================
python ./mcp_carbon_ingest.py sync --target gcp --db ./mcp_alpha_vault.sqlite3 \
  --bucket "<your-bucket>" --impersonate-sa "<worker>@<your-project-id>.iam.gserviceaccount.com" --apply
```
