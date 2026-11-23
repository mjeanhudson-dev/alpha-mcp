# First Live Push Plan & Day-1 Yield Specification (`alpha-mcp` + `scroll-craft` + `eloquentwin.com`)

- **Author & Maintainer:** `Eloquent` (`@mjeanhudson-dev`)
- **Release Plan Version:** `2.0.0` (End-User-Agnostic Public Release — Stage 1 Verified)
- **Canonical Artifact Path:** `./FIRST_LIVE_PUSH_PLAN.md`
- **Public Hygiene Status:** 100% `--strict-agnostic` clean (`Eloquent` / `@mjeanhudson-dev`; all paths normalized to `./` or `~/`; zero local OS usernames; zero raw secrets; zero private machine assumptions; intact GFM tables).
- **Companion Guides:** [README](./README.md) · [Interactive Walk-Along Guide](./walk-along/index.html) · [User Tutorial Guide](./USER_TUTORIAL_GUIDE.md) · [Master Compendium](./MASTER_COMPENDIUM.md) · [Inference Layer Spec](./INFERENCE_LAYER_SPEC.md)

---

## Executive Answer — What Will the First Live Push Yield?

Executing **First Live Push (Push #1)** delivers **three synchronized, immediately usable production tracks** on Day 1 while keeping heavy local disk images, multi-MB PDFs, backup archives, SQLite vault binaries, and secret-bearing raw transcripts strictly quarantined off-Git:

1. **Track A1 — Public End-User-Agnostic `alpha-mcp` Repository (`github.com/mjeanhudson-dev/alpha-mcp`):**
   - Ships a zero-dependency Python stdlib Stage 0 indexing and BM25 FTS5 research vault engine (`./mcp_carbon_ingest.py`) that any developer or team can clone and execute in under 60 seconds against `./examples/sample_workspace/` or their own local repositories.
   - Ships a complete hands-on onboarding bundle: the interactive 4-step **Walk-Along Guide** (`./walk-along/index.html`), the enriched **User Tutorial Guide** (`./USER_TUTORIAL_GUIDE.md`), the public front door (`./README.md`), progressive LOD `0 -> 1 -> 2` architecture specs (`./MASTER_COMPENDIUM.md`, `./INFERENCE_LAYER_SPEC.md`), runnable sample fixtures (`./examples/sample_workspace/` + `./examples/sample_ingest_report.json`), and this verified release runbook (`./FIRST_LIVE_PUSH_PLAN.md`).
   - Enforces `--strict-agnostic` pre-push hygiene (`exit=0`) and a hardened `./.gitignore` so local SQLite vaults, `.vhdx` disk images, PDFs, `.zip` archives, `.pkl` files, local audit reports, and temporary browser screenshot/profile directories are never committed.
2. **Track A2 — Hardened `scroll-craft` Plugin (`v0.3.1+stagger`):**
   - Delivers the verified `data-sc-stagger` (`revealFlowEl`) engine fix and E2E regression test (`scrollcraft.js` `92369dfe311f1eb8`, `scrollcraft.css` `da17381cb5e3a836`, `tests/engine-e2e.test.mjs`) committed cleanly as `443a97f` on top of sanitized baseline `0962df9`.
   - Verified locally with **`17/17` full Playwright + Chrome + FFmpeg tests passing (`0` fail, `0` skipped, `51.35` s)** and **`verify-public-push.mjs --strict-agnostic` exit `0` (`45` files, `0` errors)**.
   - **Stage-1 Live Push Verified:** Pushed non-destructively to branch `release/v0.3.1-stagger-sanitized` (`https://github.com/mjeanhudson-dev/scroll-craft/tree/release/v0.3.1-stagger-sanitized`, commit `443a97f`), leaving upstream `main` (`75d81f74e8`) untouched.
3. **Track B — Live `https://eloquentwin.com` Squarespace Production Launch (Gate G-04 CLEARED):**
   - Both `squarespace-inline/` (`0` `/s/` uploads — recommended Path 1) and `squarespace-s/` (`3` content-hashed `/s/` split assets — Path 2) have been **repacked and verified** from the post-stagger-fix source (`index.html` `111,032` B `0f095bf65b91b00b`, `scrollcraft.js` `66,717` B `92369dfe311f1eb8`, `scrollcraft.css` `19,874` B `da17381cb5e3a836`).
   - Verified `PACK_INLINE_HAS_STAGGER_FIX=True` and `PACK_S_HAS_STAGGER_FIX=True` (`revealFlowEl` present in both bundles), `VERIFIED_LOSS_AND_PARITY_PROOF.json` refreshed, and `verify-public-push.mjs` passed (`exit=0`, `19` files). Ready for direct Squarespace paste to go live on `https://eloquentwin.com`.
4. **Track C — Local Sovereign `v5.0.0-nexus` MCP / A2A Control Plane (Runtime Only in Push #1):**
   - Operates live over local `stdio` (`15` prefix-pinned MCP tools `#01..#15`, `19` governing equations, `4` MCP resources, `2` prompts, `2` SEP-2640 atomic skills `<= 4,500` tok, `25` HTTP/OAuth 2.1/A2A `v1.0.1` routes, `--selftest` PASS).
   - Remains local runtime only during Push #1 (excluded from public Git until server-side identity scrub and Phase 1B hardening land). Optional HTTPS tunnel exposure (`https://mcp.eloquentwin.com`) stays fail-closed until `MCP_BEARER_TOKEN` and `STATIC_OAUTH_SECRET` environment variables are configured.

---

## 1. Concrete Day-1 Yield Matrix (Push #1 Deliverables)

| Release Track | Target Repo / Live Surface | Measurable Artifacts Delivered | Verified Live Capabilities Unlocked | Stage-1 Verified Status |
| --- | --- | --- | --- | --- |
| **Track A1 — Public `alpha-mcp` Repo** | `github.com/mjeanhudson-dev/alpha-mcp` (from `~/alpha-mcp/`) | `README.md`, `walk-along/index.html` (+ local assets/icons/`share.jpg`), `USER_TUTORIAL_GUIDE.md`, `MASTER_COMPENDIUM.md`, `INFERENCE_LAYER_SPEC.md`, `FIRST_LIVE_PUSH_PLAN.md`, `mcp_carbon_ingest.py`, `examples/sample_workspace/`, `examples/sample_ingest_report.json`, `.gitignore` | Out-of-the-box zero-pip-dependency Stage 0 indexer (mmap SHA-256 dedup, `< 5` ms SQLite WAL + BM25 FTS5 retrieval over `<= 160`-line AST slices, safe read-only `.vhdx`/`.zip` inspection, pre-index secret sieve, interactive 4-step Walk-Along UI, universal tutorial) | **STAGE 2 QUEUED** (pending verifier `[verified-for-push]` sign-off) |
| **Track A2 — Hardened `scroll-craft` Plugin** | `github.com/mjeanhudson-dev/scroll-craft` (`release/v0.3.1-stagger-sanitized`) | `45` strict-agnostic files; commit `443a97f` (`+43/-14` L across `scrollcraft.js`, `scrollcraft.css`, `tests/engine-e2e.test.mjs`) on sanitized base `0962df9` | Cross-agent web motion plugin (Antigravity, Gemini CLI, Claude Code, Codex) with verified `revealFlowEl` stagger fix (`17/17` full Playwright tests PASS, `0` skipped, `51.35` s), Windows-native Node `ffmpeg.mjs`, and Squarespace packager | **PUSHED LIVE (`443a97f`)** on `release/v0.3.1-stagger-sanitized` (upstream `main` `75d81f74e8` untouched) |
| **Track B — `eloquentwin.com` Squarespace Launch** | Live URL `https://eloquentwin.com` (from `~/eloquentwin-site/`) | Repacked `squarespace-inline/` (`blank-page-head.html` `25,029` B `e31f6cc4c9664dd0` + `blank-page-body.html` `172,751` B `a8c4ac42c77ea5cf`, `0` uploads) + repacked `squarespace-s/` (`blank-page-head.html` `5,198` B `91b21715238197e0`, `blank-page-body.html` `106,067` B `eea4f2c6add3608b`, `3` hashed `/s/` assets including `*-92369dfe.js` & `*-da17381c.css`) + refreshed `VERIFIED_LOSS_AND_PARITY_PROOF.json` | Full Obsidian/Champagne studio (`7/7` sections, `33/33` controls, `13/13` copy anchors, zero video upload bloat) + sanitized 3-tab MCP Nexus Inspector (`15` tools, `19` equations, `6`-Epoch ledger) + live Scope Builder with verified `revealFlowEl` stagger reveals | **REPACKED & VERIFIED** (`PACK_INLINE_HAS_STAGGER_FIX=True`, `PACK_S_HAS_STAGGER_FIX=True`, hygiene `exit=0`; ready for Squarespace paste) |
| **Track C — Local `v5.0.0-nexus` MCP Control Plane** | Local `stdio` + optional authenticated HTTPS (`https://mcp.eloquentwin.com`) | Live local `v5.0.0-nexus` MCP server (`15` pinned tools, `19` equations, `25` HTTP/OAuth 2.1/A2A routes) + companion telemetry sidecar (`4` tools) | Sub-5ms local JSON-RPC tooling, SEP-2640 atomic skills (`<= 4,500` tok), signed A2A `v1.0.1` Agent Card, strict Stage-0-to-Apex routing, and `25:1` compaction gate | **LOCAL RUNTIME LIVE** (held off public Git pending Phase 1B hardening) |

### Reference Workstation Benchmark Snapshot (Private Archive Validation)

When benchmarked locally on the reference workstation against a private heterogeneous archive (`~808` MiB of `.vhdx`, PDFs, `.zip`, and source transcripts — **excluded from Git**), Stage 0 ingestion delivered:

| Benchmark Dimension | Reference Measured Result | Reproducible by Any Cloner? |
| --- | --- | --- |
| Ingest Speed (`mcp_carbon_ingest.py`) | `0.72` s across `15` worker threads (`parity=7bbc4e68e2f5358f`) | Yes — verified on `./examples/sample_workspace/` in `0.31` s (`parity=5ee0d39b62b63f02`, `6` files / `1` dedup / `4` slices / `9` links / `2` `ENV_SECRET` redacted) |
| Scrubbed Stage 0 Index | `19` text files (`16` unique, `3` SHA-256 dedup-shunted) -> `325` `<= 160`-line FTS5 slices (`4.09` MiB WAL) | Yes — deterministic BM25 FTS5 (`< 5` ms query latency) |
| Archive & Disk Inspection Without Unpacking | `547` `.zip` entries (`8` zips, `30.89` MiB) + `3` `.vhdx` GPT entries (`2` images, `616.0` MiB physical, `0` B unpacked) | Yes — stdlib `zipfile` + optional `7z l -slt` inspect mode |
| Pre-Index Secret Sieve | `31` sensitive hits redacted across `7` raw files -> **`0` unredacted secrets in `slices_fts`** | Yes — validated on `./examples/sample_workspace/` fixture |

---

## 2. Explicit Exclusions, Quarantine Boundary & Push #2 Deferrals

### 2.1 Strictly EXCLUDED / Quarantined from Push #1

All categories below are enforced via `./.gitignore` and the Read-Only Source Boundary so no public repository ever ingests binary bloat, ephemeral UI caches, or private credentials:

| Excluded Category | What Stays Local / Quarantined | Why Excluded | Enforcement Control |
| --- | --- | --- | --- |
| **Local SQLite Vaults** | `*.sqlite3`, `*.sqlite3-*`, `*.db`, `*.db-*` | Binary runtime indexes; reproducibly rebuilt in `< 1` s from source directories | Ignored in `./.gitignore` |
| **Virtual Disk Images** | `*.vhdx`, `*.vhd`, `vhdx_selective_stage/` | Multi-hundred-MB binary images (reference probe confirmed `0` user files in empty NTFS Dev Drive image) | Ignored in `./.gitignore`; inspect-only metadata |
| **Multi-MB Media & Archives** | `*.pdf`, `*.zip`, `*.pkl` | Binary repo bloat & unsafe binary serialization (never unpickle untrusted `.pkl` files) | Ignored in `./.gitignore` |
| **Local Personal Audit Reports** | Local workstation `ingest_report.json` (private paths/URLs) | Keeps private corpus filenames off public Git while shipping sanitized `./examples/sample_ingest_report.json` | Ignored in `./.gitignore`; public fixture tracked under `./examples/` |
| **Ephemeral UI & Build Caches** | `.taste-skill/`, `walk-along/.taste-skill/`, `walk-along/shots/`, `__pycache__/`, `*.pyc`, `.venv/` | Ephemeral headless browser profiles, debug captures, and Python bytecode | Ignored in `./.gitignore` |
| **Raw Secret-Flagged Sources** | Any raw transcript or server source flagged by `secret_audit` or failing `verify-public-push.mjs` | Zero-leak security invariant; raw credentials never enter Git or cloud sync | Blocked by `verify-public-push.mjs --strict-agnostic` |

### 2.2 Explicitly Deferred to Push #2 / Phase 2

| Deferred Workstream | Why Deferred Out of Push #1 | Concrete Unlock Prerequisite for Push #2 |
| --- | --- | --- |
| **Databricks `setup-local` & Unity Catalog Sync (`Slot #19`)** | `Python 3.15.0` and `uv 0.13.1` are ready, but **Databricks CLI (`>= v1.16.0`) is NOT installed** and no workspace OAuth profile is configured yet. | Install CLI (`winget install Databricks.DatabricksCLI` or `brew install databricks/tap/databricks`), verify `>= v1.16.0`, run `databricks auth login`, then `databricks environments setup-local`. |
| **MCP Server Phase 1B Hardening & Phase 1C Tail Slots (`#16–#18`)** | Keeps live `v5.0.0-nexus` stable during Push #1 baseline publication. | Scrub remaining identity literals, unify all `12` credential redaction classes, add secret-path airlock, and append tail-pinned vault/edge tools (`#16–#18`) without mutating Slots `#01..#15`. |
| **Optional PDF OCR & Chunking** | Requires non-stdlib OCR libraries and multi-minute processing; unnecessary for Day-1 launch. | Optional Phase-2 local OCR pipeline emitting scrubbed `<= 160`-line slices into local SQLite FTS5. |
| **Selective `.vhdx` Extraction** | Reference read-only GPT + `$MFT` probe confirmed selective extraction was unnecessary (`0` user files). | Invoked only if a user explicitly passes `--vhdx-mode selective-extract` on a populated virtual disk. |

---

## 3. Go / No-Go Gate Table (Push #1 Release Checklist)

| Gate ID | Track / Surface | Invariant Checked | Verification Command / Parity Proof | Pass Criteria (GO) | Current Status |
| --- | --- | --- | --- | --- | --- |
| **G-01** | Track A1 (`~/alpha-mcp`) | Out-of-the-box end-user smoke test (`sample_workspace`) & `py_compile` | `python -m py_compile ./mcp_carbon_ingest.py` + `python ./mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db <temp.sqlite3>` + `query` + `audit` | Exit `0`; FTS5 active; redaction fixture scrubbed; `0` raw secrets in `slices_fts` | **VERIFIED IN STAGE 1 -> RE-VERIFIED BY VERIFIER** |
| **G-02** | Track A1 (`~/alpha-mcp`) | 100% `--strict-agnostic` hygiene + Walk-Along `GATE: PASS` | `node "$HOME/tools/verify-public-push.mjs" "$HOME/alpha-mcp" --strict-agnostic` + `design-taste-frontend` `gate.mjs` on `./walk-along/index.html` | `verify-public-push.mjs --strict-agnostic` exit `0` (`errors=0`); `GATE: PASS`; zero binaries/secrets staged in `git status` | **PENDING VERIFIER `[verified-for-push]`** |
| **G-03** | Track A2 (`scroll-craft`) | Full Playwright test suite, `--strict-agnostic` gate, commit & remote push | `$env:SCROLLCRAFT_PLAYWRIGHT="$HOME/.gemini/antigravity/scratch/scroll-craft"; node --test (Get-ChildItem "$HOME/.gemini/config/plugins/scroll-craft/tests/*.test.mjs").FullName` + `verify-public-push.mjs --strict-agnostic` | `17/17` tests PASS (`0` fail, `0` skipped); strict-agnostic exit `0` (`45` files); committed as `Eloquent` (`443a97f`); pushed to `release/v0.3.1-stagger-sanitized` | **PASS (LIVE ON GITHUB `443a97f`)** |
| **G-04** | Track B (`~/eloquentwin-site`) | Repacked `squarespace-inline/` & `squarespace-s/` contain `revealFlowEl` fix & matching SHA-256s | Repack via `squarespace-pack.mjs`, verify `PACK_INLINE_HAS_STAGGER_FIX=True` & `PACK_S_HAS_STAGGER_FIX=True`, confirm `*-92369dfe.js` & `*-da17381c.css`, run `verify-public-push.mjs` | Both bundles contain `revealFlowEl`; exact SHA-256 parity (`92369dfe311f1eb8` / `da17381cb5e3a836`); `VERIFIED_LOSS_AND_PARITY_PROOF.json` updated; hygiene exit `0` (`19` files) | **PASS (CLEARED IN STAGE 1)** |
| **G-05** | Track B (`eloquentwin.com` Live) | Manual Squarespace paste, desktop/mobile render, and editor preservation | Paste `squarespace-inline/blank-page-head.html` & `blank-page-body.html` into Squarespace Editor (`Core`/`Business+` plan), verify `1440x900` & `390x844` | All stagger grids reveal cleanly; 3-tab MCP Nexus filters smoothly; Scope Builder SMS/Copy works; `sqs-edit-mode-active` stays editable | **READY FOR OPERATOR PASTE** |
| **G-06** | Track C (`v5.0.0-nexus` MCP) | Local `--selftest`, auth env gate before HTTPS tunnel, no uncleaned public Git push | `python <mcp_server> --selftest`; require non-empty auth env vars prior to HTTP/tunnel startup | `--selftest` PASS; stays local runtime only in Push #1 | **PASS FOR LOCAL STDIO** |
| **G-07** | Phase 2 (Databricks Bridge) | CLI `>= v1.16.0` + OAuth profile | `databricks --version` + `uv --version` | `uv 0.13.1` PASS; `databricks` CLI not installed -> deferred cleanly to Push #2 | **DEFERRED (NON-BLOCKING)** |

### Verified Stage-1 SHA-256 Parity Snapshot (Track B & Track A2)

| Track | Canonical Artifact (`~/...`) | Verified Bytes | Verified SHA-256 Prefix | Stage-1 Parity Proof |
| --- | --- | --- | --- | --- |
| **Track B** | `~/eloquentwin-site/index.html` | `111,032` | `0f095bf65b91b00b` | Post-stagger-fix source (`+26,912` B over baseline `84,120` B) |
| **Track B** | `~/eloquentwin-site/scrollcraft.js` | `66,717` | `92369dfe311f1eb8` | Exact match with `scroll-craft` engine & `squarespace-s/upload-to-s/*-92369dfe.js` |
| **Track B** | `~/eloquentwin-site/scrollcraft.css` | `19,874` | `da17381cb5e3a836` | Exact match with `scroll-craft` engine & `squarespace-s/upload-to-s/*-da17381c.css` |
| **Track B** | `~/eloquentwin-site/squarespace-inline/blank-page-head.html` | `25,029` | `e31f6cc4c9664dd0` | Repacked inline head (verified `verify-public-push.mjs` exit `0`) |
| **Track B** | `~/eloquentwin-site/squarespace-inline/blank-page-body.html` | `172,751` | `a8c4ac42c77ea5cf` | Repacked inline body (`PACK_INLINE_HAS_STAGGER_FIX=True`, `revealFlowEl` verified) |
| **Track B** | `~/eloquentwin-site/squarespace-s/blank-page-head.html` | `5,198` | `91b21715238197e0` | Repacked `/s/` head |
| **Track B** | `~/eloquentwin-site/squarespace-s/blank-page-body.html` | `106,067` | `eea4f2c6add3608b` | Repacked `/s/` body (`PACK_S_HAS_STAGGER_FIX=True`, saves `66,684` B vs inline) |
| **Track A2** | `~/.gemini/config/plugins/scroll-craft` (`HEAD`) | `45` files | Commit `443a97f` | `17/17` Playwright tests PASS + `--strict-agnostic` exit `0` |

---

## 4. Ordered Execution Runbook (Universal PowerShell Commands)

Every command below uses normalized `$HOME/` paths and mandatory `# LABEL / # USE / # MECHANISM_OF_ACTION` headers.

### Step 1 — Track B: Verify Repacked Squarespace Bundles & Publish to `eloquentwin.com`

*(Stage 1 repack & parity verification already completed; re-run only if source HTML/JS/CSS changes.)*

```powershell
# ==============================================================================
# LABEL:               Repack & Verify Squarespace Inline and Split Bundles
# USE:                 Generate up-to-date Squarespace deployment packs from ~/eloquentwin-site and confirm revealFlowEl stagger-fix parity before upload.
# MECHANISM_OF_ACTION: Cleans stale squarespace-inline and squarespace-s directories, runs scroll-craft's squarespace-pack.mjs in both --inline-engine and /s/ modes, verifies revealFlowEl presence and SHA-256 hashes, and enforces verify-public-push.mjs exit code 0.
# ==============================================================================
$ErrorActionPreference = "Stop"
$packer = "$HOME/.gemini/config/plugins/scroll-craft/skills/scroll-craft/scripts/squarespace-pack.mjs"
$siteDir = "$HOME/eloquentwin-site"
$siteUrl = "https://eloquentwin.com"
$editorUrl = "https://<your-site>.squarespace.com/config/pages"

Remove-Item -Recurse -Force "$siteDir/squarespace-inline", "$siteDir/squarespace-s" -ErrorAction SilentlyContinue

node $packer --in "$siteDir" --out "$siteDir/squarespace-inline" --site "$siteUrl" --editor-url "$editorUrl" --load direct --inline-engine
node $packer --in "$siteDir" --out "$siteDir/squarespace-s" --site "$siteUrl" --editor-url "$editorUrl" --asset-base "/s/" --load direct

node "$HOME/tools/verify-public-push.mjs" "$siteDir"
```

**Squarespace Editor Publish Steps (Recommended Path 1 — `squarespace-inline/`, `0` File Uploads):**
1. Open `https://<your-site>.squarespace.com/config/pages` (requires Squarespace **Core / Business+**).
2. On the target Blank Page, open **Page Settings -> Advanced -> Page Header Code Injection**, paste `~/eloquentwin-site/squarespace-inline/blank-page-head.html`, and click **Save**.
3. Click **Edit**, add a single full-width **Fluid Engine** section with one **Code Block** (**HTML**, **Display Source = OFF**), paste `~/eloquentwin-site/squarespace-inline/blank-page-body.html`, stretch full width, click **Save -> Exit**, and click **Set as Homepage**.
4. Verify desktop (`1440x900`), mobile (`390x844`), all 3 stagger grids, MCP Nexus tabs, Scope Builder SMS/Copy, and re-entering **Edit** mode (`body.sqs-edit-mode-active`).

### Step 2 — Track A2: Resolve `scroll-craft` Remote Divergence & Push

*(Commit `443a97f` on sanitized orphan `0962df9` is already committed and verified `17/17` Playwright + `--strict-agnostic` exit `0`.)*

```powershell
# ==============================================================================
# LABEL:               Attach Remote & Push Sanitized Scroll-Craft v0.3.1+stagger
# USE:                 Push verified local commit 443a97f to github.com/mjeanhudson-dev/scroll-craft after explicit operator approval on how to reconcile divergent remote main (75d81f74e8).
# MECHANISM_OF_ACTION: Attaches origin to https://github.com/mjeanhudson-dev/scroll-craft.git, re-verifies --strict-agnostic exit 0, and pushes either to a new clean branch (safe default) or force-updates main ONLY if explicitly approved by the repository owner.
# ==============================================================================
$ErrorActionPreference = "Stop"
$pluginDir = "$HOME/.gemini/config/plugins/scroll-craft"

node "$HOME/tools/verify-public-push.mjs" "$pluginDir" --strict-agnostic
if (-not (git -C "$pluginDir" remote)) {
  git -C "$pluginDir" remote add origin "https://github.com/mjeanhudson-dev/scroll-craft.git"
}

# Option A (Non-destructive default): publish sanitized history on a dedicated release branch
git -C "$pluginDir" push -u origin main:release/v0.3.1-stagger-sanitized

# Option B (ONLY with explicit owner approval to overwrite upstream fork history 75d81f74e8):
# git -C "$pluginDir" push --force-with-lease origin main
```

### Step 3 — Track A1 (Stage 2): Initialize, Gate & Publish Public `mjeanhudson-dev/alpha-mcp`

*(Execute ONLY after independent verifier posts `[verified-for-push]` confirming all tracked files + `./walk-along/index.html` pass `--strict-agnostic` exit `0` and `GATE: PASS`.)*

```powershell
# ==============================================================================
# LABEL:               Stage 2 Public Git Init, Strict-Agnostic Gate & Push for alpha-mcp
# USE:                 Publish ~/alpha-mcp as a 100% end-user-agnostic public GitHub repository (github.com/mjeanhudson-dev/alpha-mcp) with zero binaries, zero local reports, and zero personal leaks.
# MECHANISM_OF_ACTION: Initializes branch main with Eloquent author identity, verifies git status contains only clean tracked files, runs verify-public-push.mjs --strict-agnostic (requiring exit 0), commits, and creates/pushes the public GitHub repository via gh repo create.
# ==============================================================================
$ErrorActionPreference = "Stop"
$repoDir = "$HOME/alpha-mcp"

if (-not (Test-Path "$repoDir/.git")) {
  git -C "$repoDir" init -b main
}
git -C "$repoDir" config user.name "Eloquent"
git -C "$repoDir" config user.email "mjeanhudson@users.noreply.github.com"

git -C "$repoDir" add -A
git -C "$repoDir" status --short

# Hard pre-push gate: EVERY tracked file MUST exit 0 in --strict-agnostic mode
# (Iterates git ls-files so gitignored local artifacts like local ingest_report.json are excluded;
#  on a fresh clone, running verify-public-push.mjs "$repoDir" --strict-agnostic directly also exits 0.)
git -C "$repoDir" ls-files | ForEach-Object {
  $f = Join-Path $repoDir $_
  if ($f -match '\.(md|mjs|js|cjs|ts|tsx|json|ps1|sh|py|html|css|ya?ml|txt|cmd)$') {
    node "$HOME/tools/verify-public-push.mjs" "$f" --strict-agnostic
    if ($LASTEXITCODE -ne 0) { throw "STRICT_AGNOSTIC_FAIL: $_" }
  }
}

git -C "$repoDir" commit -m "feat(alpha-mcp): public Stage 0 Carbon indexer, interactive walk-along UI, tutorial, and inference specs"
gh repo create mjeanhudson-dev/alpha-mcp --public --source="$repoDir" --remote=origin --push
```

### Step 4 — Phase 2 (Deferred): Optional Databricks CLI & Local Compute Bootstrap

Execute **only after Push #1 is live** when ready to add cloud lakehouse / Unity Catalog federation:

```powershell
# ==============================================================================
# LABEL:               Phase-2 Databricks CLI Install, OAuth Login & Local Env Bootstrap
# USE:                 Install Databricks CLI >= v1.16.0 alongside uv 0.13.1 to unlock optional Phase-2 Unity Catalog synchronization (Slot #19).
# MECHANISM_OF_ACTION: Installs Databricks.DatabricksCLI via WinGet, checks semantic version >= 1.16.0, runs browser OAuth login against the target workspace, and executes databricks environments setup-local.
# ==============================================================================
winget install Databricks.DatabricksCLI
databricks --version
databricks auth login --host https://<your-workspace>.cloud.databricks.com
databricks environments setup-local
```

---

## 5. Stage-1 Handoff & Operator Decision Matrix

| Track / Item | Stage-1 Verified Outcome | Next Action |
| --- | --- | --- |
| **Track B (`eloquentwin.com` Repack)** | **COMPLETE & VERIFIED** (`PACK_INLINE_HAS_STAGGER_FIX=True`, `PACK_S_HAS_STAGGER_FIX=True`, `VERIFIED_LOSS_AND_PARITY_PROOF.json` refreshed, hygiene `exit=0`) | Verifier headless-Chrome check -> operator pastes `squarespace-inline/` into Squarespace |
| **Track A2 (`scroll-craft` `v0.3.1+stagger`)** | **PUSHED LIVE & VERIFIED** (`443a97f` on `release/v0.3.1-stagger-sanitized`; `17/17` Playwright tests PASS; `--strict-agnostic` `exit=0`; upstream `main` `75d81f74e8` untouched) | Verifier confirms remote branch & `17/17` suite |
| **Track A1 (`alpha-mcp` Public Repo)** | `FIRST_LIVE_PUSH_PLAN.md` updated to 100% `--strict-agnostic` clean; awaiting `@walkalong-ui`, `@compendium`, `@ingestor` + verifier `[verified-for-push]` | Immediately run Stage 2 `git init` -> `verify-public-push.mjs --strict-agnostic` -> `gh repo create mjeanhudson-dev/alpha-mcp --public --push` |
| **Track C & Phase 2 (Local MCP & Databricks)** | Local stdio MCP live; Databricks CLI not installed | Hold server off public Git until Phase 1B scrub; defer Databricks `setup-local` to Push #2 |
