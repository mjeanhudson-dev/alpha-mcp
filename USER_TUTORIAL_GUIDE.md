# Alpha MCP — User Tutorial Guide, Best Practices & Possibilities

- **Author & Maintainer:** `Eloquent` (`@mjeanhudson-dev`)
- **Guide Version:** `1.0.0` (universal, end-user agnostic, zero `pip` dependencies)
- **Runtime Requirement:** Python `3.10+` standard library only *(optional: `7-Zip` for `.vhdx` virtual disk inspection)*
- **Interactive Companion:** Open [`./walk-along/index.html`](./walk-along/index.html) alongside this guide to explore every stage visually.

---

## 1. 60-Second Zero-Dependency Quick Start

Clone the repository and run Stage 0 ingestion against the bundled, self-contained [`./examples/sample_workspace/`](./examples/sample_workspace/) fixture. Zero third-party packages are required and nothing inside the source folder is modified.

### Step 1 — Ingest the Sample Workspace (PowerShell or Bash)

```powershell
# ==============================================================================
# LABEL:               60-Second Alpha MCP Sample Workspace Ingest & Verify (PowerShell)
# USE:                 Run a complete out-of-the-box Stage 0 ingest, security audit, and BM25 FTS5 query against ./examples/sample_workspace using Python 3.10+ stdlib only.
# MECHANISM_OF_ACTION: Invokes mcp_carbon_ingest.py across 6 bundled sample files (Python AST, byte-identical duplicate, Markdown links, Jupyter .ipynb, Chrome .url shortcut, and safe ENV_SECRET fixture) into a local SQLite WAL + FTS5 database.
# ==============================================================================
python ./mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db ./sample_vault.sqlite3
python ./mcp_carbon_ingest.py audit --db ./sample_vault.sqlite3
python ./mcp_carbon_ingest.py query 'mcp' --db ./sample_vault.sqlite3 --top 5
python ./mcp_carbon_ingest.py query 'ast_summary:LocalResearchMCPServer' --db ./sample_vault.sqlite3 --top 5
```

```bash
# ==============================================================================
# LABEL:               60-Second Alpha MCP Sample Workspace Ingest & Verify (Bash / Zsh)
# USE:                 Run the identical zero-dependency quick start on macOS or Linux.
# MECHANISM_OF_ACTION: Executes mcp_carbon_ingest.py ingest, audit, and BM25 FTS5 query subcommands against ./examples/sample_workspace into a temporary local SQLite WAL vault.
# ==============================================================================
python3 ./mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db ./sample_vault.sqlite3
python3 ./mcp_carbon_ingest.py audit --db ./sample_vault.sqlite3
python3 ./mcp_carbon_ingest.py query 'mcp' --db ./sample_vault.sqlite3 --top 5
python3 ./mcp_carbon_ingest.py query 'ast_summary:LocalResearchMCPServer' --db ./sample_vault.sqlite3 --top 5
```

### Step 2 — Verify Your Telemetry Receipt Against Ground Truth

Your `ingest` command emits a compact `< 300`-token Stage 0 receipt. Compare your values directly with [`./examples/sample_ingest_report.json`](./examples/sample_ingest_report.json):

| Receipt Field | Expected Sample Value | What It Proves |
| --- | --- | --- |
| `parity` | `5ee0d39b62b63f02` | Deterministic digest `sha256("6:4:9:2")[:16]` verified end-to-end |
| `files` / `dedup_shunted` | `6` / `1` | `backup/demo_mcp_server_copy.py` matched `demo_mcp_server.py` (`c3f45e8ef47cb9a9`) via `mmap` SHA-256 and emitted zero duplicate FTS5 rows |
| `slices_160L` | `4` | Clean `<= 160`-line slices across Markdown, Python, stripped `.ipynb`, and scrubbed text (`links.url` stores link rows only) |
| `links` | `9` | `6` `notebook_or_mcp_hub` URLs + `3` `web_reference` URLs harvested from `.md`, `.ipynb`, and `.url` |
| `secrets_redacted` | `2` | Both `ENV_SECRET` placeholders in `config_redaction_demo.txt` replaced with `[REDACTED:ENV_SECRET]`; `0` raw values in `slices_fts` |
| `fts5_active` / `status` | `True` / `SCRUBBED_SAFE_INDEX` | SQLite `porter unicode61` BM25 full-text index live and scrubbed |

Clean up your temporary test database at any time (`.sqlite3*` is already excluded by `.gitignore`):

```powershell
# ==============================================================================
# LABEL:               Clean Up Temporary Sample SQLite Vault Files
# USE:                 Remove sample_vault.sqlite3 and its SQLite WAL sidecar files after completing the 60-second quick start.
# MECHANISM_OF_ACTION: Deletes matching sample_vault.sqlite3* files from the repository root without touching tracked files or ./examples/sample_workspace.
# ==============================================================================
Remove-Item -Force -ErrorAction SilentlyContinue ./sample_vault.sqlite3*
```

---

## 2. Companion Walkthrough of `./walk-along/index.html`

Alpha MCP ships with an interactive, static-HTML Walk-Along Guide at [`./walk-along/index.html`](./walk-along/index.html). You can open it directly or serve it on loopback for zero-CORS friction:

```powershell
# ==============================================================================
# LABEL:               Serve Interactive Walk-Along Guide on Localhost
# USE:                 Launch a local HTTP preview server for ./walk-along/index.html so interactive assets and step states render identically across browsers.
# MECHANISM_OF_ACTION: Uses Python stdlib http.server bound strictly to loopback 127.0.0.1 on port 8787 serving ./walk-along.
# ==============================================================================
python -m http.server 8787 --bind 127.0.0.1 --directory ./walk-along
# Open http://127.0.0.1:8787/index.html in your browser
```

### Following the 4 Interactive Walk-Along Steps

| Walk-Along Step | Visual Interactive Preview | Matching CLI / Architecture Action |
| --- | --- | --- |
| **Step 1 — Point & Inspect** | Select source roots, inspect `.vhdx` and `.zip` manifests without extracting gigabytes | `python mcp_carbon_ingest.py ingest --roots <dirs...> --vhdx-mode inspect` |
| **Step 2 — Scrub & 160-Line Slice** | Inspect live before/after secret redaction, `mmap` SHA-256 deduplication, and Python AST skeleton extraction | Automatic inside `process_single_file()` (`ast.parse` -> `scrub_secrets` -> `slice_text_160`) |
| **Step 3 — Query BM25 FTS5** | Run sub-5ms ranked searches, column filters (`ast_summary:`, `path:`), and audit tables | `python mcp_carbon_ingest.py query '<expr>' --top 5` & `audit` |
| **Step 4 — Wire MCP & Push Clean** | Append tail-pinned MCP tools (Slots `#16+`) without breaking KV prefix caches and gate pushes | See [`INFERENCE_LAYER_SPEC.md`](./INFERENCE_LAYER_SPEC.md) & Section 5 below |

---

## 3. Stage 0 Carbon Best Practices

Stage 0 pushes deterministic I/O, hashing, parsing, redaction, and ranking into local Python + SQLite (`0` LLM tokens) so frontier reasoning models receive only high-signal, bounded payloads (`<= 160`-line slices and `< 300`-token telemetry deltas).

### 3.1 Zero-Copy `mmap` SHA-256 Deduplication

- **How it works:** `compute_mmap_sha256()` maps each file read-only (`mmap.ACCESS_READ`) and streams `4 MiB` chunks into SHA-256 (short-circuiting cleanly on `0`-byte files).
- **Why it matters:** Research directories routinely accumulate duplicate backups, exported snapshots, and mirrored scripts. Alpha MCP records every path in `files` (`is_duplicate = 1` for repeats) but emits **zero** duplicate chunks into `slices_fts`, preventing noisy BM25 score distortion and cutting vault size.
- **Best practice:** Always pass multiple related roots in a single `--roots dirA dirB dirC` call so cross-folder duplicates are shunted immediately in one pass.

### 3.2 Three-Mode Safe `.vhdx` Handling & Zero-Extraction `.zip` Inventory

Never blindly extract multi-gigabyte `.vhdx` virtual disks or nested `.zip` archives into your working repo. `mcp_carbon_ingest.py` supports three explicit `--vhdx-mode` strategies plus automatic stdlib `zipfile` cataloging:

| `--vhdx-mode` | External Tool | Disk Footprint | When to Use |
| --- | --- | --- | --- |
| `inspect` *(default)* | `7z l -slt` (`7-Zip`) | **`0` B unpacked** | **Always start here.** Lists GPT partitions, file systems, offsets, and entry sizes into `vhdx_manifest`. In the reference workstation benchmark (`616.0` MB across `2` `.vhdx` files), read-only probing proved one 50 GiB NTFS volume had `0` user files (`28` system `$MFT` records), eliminating wasted extraction. |
| `selective-extract` | `7z x` with strict allow/deny globs | Small text subset only | Use **only** after `inspect` confirms real code/docs inside a disk image. Extracts strictly `.py`, `.sh`, `.md`, `.ipynb`, `.json`, `.toml`, `.yaml`, `.url` into `--extract-dir` (gitignored) while excluding `node_modules`, `.git`, `.venv`, and `__pycache__`. |
| `mount-command` | None (generates commands) | **`0` B unpacked** | Air-gapped or no-7z hosts: logs safe read-only `Mount-DiskImage -ReadOnly` (PowerShell) and `wsl --mount --vhd ... --bare` commands into `vhdx_manifest` for operator-controlled mounting. |

Meanwhile, all `.zip` archives are inspected via Python's stdlib `zipfile` into `zip_manifest` (`entry_path`, `entry_size`, `compressed_size`) with **zero extraction** (capped at `10,000` entries per archive to guard against zip bombs).

### 3.3 Native `.ipynb` Base64 Output Stripping

Jupyter notebooks frequently embed multi-megabyte base64 PNG plots, HTML tables, and execution traces inside cell `outputs`. `parse_ipynb_native()` parses `.ipynb` JSON natively in Python (zero `jupyter nbconvert` subprocesses), discards all `outputs`, and indexes only non-empty `MARKDOWN` and `CODE` cell sources prefixed with `# --- [CELL N | TYPE] ---`. This preserves 100% of executable code and prose while preventing token and index bloat.

### 3.4 `<= 160`-Line Deterministic AST Slicing

- **AST Before Redaction:** For every `.py` file, `extract_python_ast_header()` runs `ast.parse()` on the original source **before** secret redaction so syntax remains valid (even if a secret literal is replaced by `[REDACTED:...]`), then scrubs the resulting summary string before storage. Files with genuine syntax truncation emit a clean `[AST_SYNTAX_WARN line=N]` marker instead of crashing the worker pool.
- **LOD-1 Skeletons on Chunk 0:** Top-level docstrings, class names with up to `8` methods, and function signatures with line numbers (`L14`, `L25`) are stored in `files.ast_summary` and attached to `chunk_index = 0` in `slices_fts`. Agents can search class/function contracts first before ever pulling a body slice.
- **160-Line Ceiling:** `slice_text_160()` bounds every indexed chunk to `<= 160` lines (`L1-L160`, `L161-L320`, ...), ensuring any retrieved slice fits comfortably inside a tight LLM tool-response budget (`<= 1,500` tokens).

### 3.5 Pre-Share 12-Pattern Credential Sieve & Metadata-Only Audit

Never rely on human eyesight to keep credentials out of an index or Git repository:

1. **9 Built-In Stage 0 Redaction Classes (`mcp_carbon_ingest.py`):**
   - `GOOGLE_API_KEY`, `GOOGLE_OAUTH_TOKEN`, `ANTHROPIC_KEY` *(ordered strictly ahead of generic `OPENAI_KEY` so `sk-ant-*` is never misclassified)*, `OPENAI_KEY`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY`, `SLACK_TOKEN`, `PRIVATE_KEY`, and `ENV_SECRET`.
2. **3 Additional Runtime Control-Plane Classes (`INFERENCE_LAYER_SPEC.md`):**
   - `BEARER_TOKEN` (`Authorization: Bearer ...`), `SENTRY_TOKEN`, and internal OAuth access/refresh/code tokens — yielding a unified **12-pattern** defense-in-depth contract across both ingest and live MCP responses.
3. **Metadata-Only `secret_audit` Table:**
   - Records **only** `(source_path, secret_type, line_number)` — raw secret values are never stored in `secret_audit` or `slices_fts`.
4. **Quarantine Discipline:**
   - Any raw source file appearing in `mcp_carbon_ingest.py audit` MUST stay out of public Git commits, cloud syncs, and raw prompt dumps. Pair this with a runtime `is_secret_path()` airlock blocking `.env`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, and `*.kdbx`.

---

## 4. BM25 FTS5 Query Cookbook (PowerShell & Bash Escaping)

`slices_fts` uses SQLite FTS5 with the `porter unicode61` tokenizer (stemming + case-insensitive Unicode folding) across indexed columns `path`, `folder_root`, `ast_summary`, and `content` (`chunk_index` and `line_range` are stored `UNINDEXED` for zero-cost display).

### 4.1 High-Value Query Patterns

| Goal | FTS5 Expression | Notes |
| --- | --- | --- |
| Simple keyword & stemmed search | `mcp` | Matches `mcp`, `MCP`, etc., ranked by BM25 |
| Boolean intersection | `sqlite AND fts5` | Both terms must appear in the same `<= 160`-line slice |
| Boolean union | `scrollcraft OR squarespace` | Either term matches; slices containing both rank higher |
| Exclusion | `oauth NOT legacy` | Excludes slices containing `legacy` |
| Prefix wildcard | `redac*` | Matches `redact`, `redacted`, `redaction` |
| Column-scoped AST jump | `ast_summary:LocalResearchMCPServer` | Hits only Python AST symbol headers (`chunk_index = 0`) |
| Path-scoped slice lookup | `path:demo_mcp_server` | Restricts results to matching file paths |
| Root-scoped search | `folder_root:sample_workspace AND sqlite` | Filters to one indexed `--roots` folder |
| Redaction marker check | `REDACTED` | Finds every slice where the secret sieve replaced a token |

### 4.2 PowerShell vs. Bash Quoting Rules (Avoiding the Hyphen Trap)

SQLite FTS5 interprets an unquoted hyphen (`-`) inside a query as a `NOT` / column operator (so bare `SEP-2640` fails with `no such column: 2640`). Always double-quote hyphenated terms inside the FTS5 expression — and account for how your shell passes quotes to Python:

```powershell
# ==============================================================================
# LABEL:               BM25 FTS5 Quoting Recipes for Windows PowerShell
# USE:                 Run boolean, column-scoped, and hyphenated phrase queries reliably from PowerShell 5.1/7 without native-argument quote stripping errors.
# MECHANISM_OF_ACTION: Passes single-quoted FTS5 expressions to mcp_carbon_ingest.py, escaping inner double quotes with backslashes for hyphenated tokens so Python receives literal quotes.
# ==============================================================================
python ./mcp_carbon_ingest.py query 'sqlite AND fts5' --db ./sample_vault.sqlite3 --top 5
python ./mcp_carbon_ingest.py query 'ast_summary:VaultConfig OR ast_summary:LocalResearchMCPServer' --db ./sample_vault.sqlite3 --top 5
python ./mcp_carbon_ingest.py query '\"SEP-2640\" OR A2A' --db ./mcp_alpha_vault.sqlite3 --top 5
```

```bash
# ==============================================================================
# LABEL:               BM25 FTS5 Quoting Recipes for Bash / Zsh (macOS & Linux)
# USE:                 Execute identical boolean, AST-scoped, and hyphenated FTS5 phrase queries under POSIX shells.
# MECHANISM_OF_ACTION: Uses single outer quotes so POSIX shells preserve literal inner double quotes verbatim when invoking python3 mcp_carbon_ingest.py.
# ==============================================================================
python3 ./mcp_carbon_ingest.py query 'sqlite AND fts5' --db ./sample_vault.sqlite3 --top 5
python3 ./mcp_carbon_ingest.py query 'ast_summary:VaultConfig OR ast_summary:LocalResearchMCPServer' --db ./sample_vault.sqlite3 --top 5
python3 ./mcp_carbon_ingest.py query '"SEP-2640" OR A2A' --db ./mcp_alpha_vault.sqlite3 --top 5
```

### 4.3 Concurrency-Safe Read-Only SQLite URI Access (For Tools & Multi-Agent Readers)

When multiple agents or editor extensions query the vault concurrently while background ingestion runs in WAL mode, open the database strictly read-only with a busy timeout:

```python
import sqlite3
from pathlib import Path

def bm25_search(db_path: Path, fts_expr: str, top_k: int = 5) -> list[tuple[str, str, float, str]]:
    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.execute("PRAGMA query_only = ON;")
        conn.execute("PRAGMA busy_timeout = 3000;")
        return conn.execute(
            """SELECT path, line_range, round(bm25(slices_fts), 3) AS score,
                      snippet(slices_fts, 5, '>>>', '<<<', ' ... ', 24)
               FROM slices_fts
               WHERE slices_fts MATCH ?
               ORDER BY rank
               LIMIT ?""",
            (fts_expr, top_k),
        ).fetchall()
```

---

## 5. Possibilities & Production Extensions

Once your Stage 0 vault is running locally, the same SQLite WAL + FTS5 core unlocks four high-leverage workflows.

### 5.1 Wire SQLite FTS5 to Any MCP Server via Tail-Pinned Tools

Frontier prompt caches depend on a byte-identical prefix (`tools/list` schema at byte offset 0). When adding vault search to an existing MCP server:

1. **Freeze existing tools:** Keep `capabilities.tools.listChanged = false` and never reorder or rename existing slots.
2. **Append strictly at the wire tail:** Add `stage0_vault_fts_query` (Slot `#16`) and `stage0_vault_manifest_lookup` (Slot `#17`) after your current tool list — see the reference JSON schemas in [`INFERENCE_LAYER_SPEC.md`](./INFERENCE_LAYER_SPEC.md) (Section 5) and the minimal runnable pattern in [`./examples/sample_workspace/demo_mcp_server.py`](./examples/sample_workspace/demo_mcp_server.py).
3. **Cap tool responses & pair with atomic skills:** Return 28-token BM25 snippets + LOD-1 `ast_summary` headers by default, capping full `<= 160`-line slices at `<= 1,500` tokens per call, and publish a compact (`< 250`-token) SEP-2640 skill instructing agents to query the vault before reading raw directories.

### 5.2 Air-Gapped Compliance & Security Audits

Because `mcp_carbon_ingest.py` uses **zero network calls** and **zero external pip packages**, you can drop the single file onto an air-gapped or regulated workstation to:
- Inventory every `.zip` and `.vhdx` container without inflating disk usage (`zip_manifest`, `vhdx_manifest`).
- Produce a metadata-only credential exposure report (`secret_audit`) pinpointing exact files and line numbers requiring secret rotation before repository sharing.
- Verify programmatically that zero unredacted credential prefixes exist in `slices_fts` prior to granting an agent read-only vault access.

### 5.3 CI / Pre-Push Public Hygiene Gates

Pair Alpha MCP's `.gitignore` discipline with an automated pre-push gate in local hooks or CI workflows:
- **Keep heavy & sensitive artifacts out of Git:** Exclude `*.sqlite3*`, `*.vhdx`, `*.pdf`, `*.zip`, `*.pkl`, `__pycache__/`, `.venv/`, and local workstation reports via `.gitignore`.
- **Enforce strict-agnostic text scans:** Block credential regexes, hardcoded local OS usernames or absolute home directory paths (requiring normalized `~/` or repo-relative paths), and malformed Markdown table column counts before every commit or pull request.
- **Run reproducible smoke tests in CI:** Execute `python mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db /tmp/ci_vault.sqlite3` and assert `parity=5ee0d39b62b63f02` and `0` unredacted secrets in `slices_fts`.

### 5.4 Phase-2 Databricks & Lakehouse Federation (Optional Cloud Scale)

When your research index grows beyond a single developer machine and a team needs shared analytics over sanitized LOD-1 metadata and scrubbed slices:

1. **Install prerequisites locally:** Pair `uv` (`>= 0.10`) with Databricks CLI `>= v1.16.0` (`winget install Databricks.DatabricksCLI` on Windows or `brew install databricks/tap/databricks` on macOS/Linux).
2. **Authenticate & bootstrap local compute:** Run `databricks auth login --host https://<your-workspace>.cloud.databricks.com` followed by `databricks environments setup-local`.
3. **Enforce a zero-leak export boundary:** Export **only** normalized `~/` metadata (`files`, `links`, `vhdx_manifest`, `zip_manifest`) and double-verified scrubbed slices to Unity Catalog (`dry_run=true` by default). Never upload raw `secret_audit`-flagged files, raw `.vhdx` images, `.pkl` binaries, or raw `.sqlite3` database binaries. Full schema and fail-closed MCP tool specifications live in [`INFERENCE_LAYER_SPEC.md`](./INFERENCE_LAYER_SPEC.md) (Sections 5 & 7).

---

## 6. Next Reading Map

| Document | Purpose |
| --- | --- |
| [`./README.md`](./README.md) | Repository overview, quick start, and architecture map |
| [`./walk-along/index.html`](./walk-along/index.html) | Interactive 4-step visual simulator & walk-along guide |
| [`./MASTER_COMPENDIUM.md`](./MASTER_COMPENDIUM.md) | Progressive LOD 0 -> LOD 1 -> LOD 2 KPPC reference architecture & workstation benchmark ledger |
| [`./INFERENCE_LAYER_SPEC.md`](./INFERENCE_LAYER_SPEC.md) | Unified Stage 0 -> MCP/A2A -> Apex Contactor -> Exodia Compaction -> Phase-2 Databricks specification |
| [`./FIRST_LIVE_PUSH_PLAN.md`](./FIRST_LIVE_PUSH_PLAN.md) | Release readiness gates, quarantine matrix, and step-by-step execution runbook |
