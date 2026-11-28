# ==============================================================================
# LABEL:               Deploy Zero-Privilege Commercial MCP to Cloud Run (us-east1)
# USE:                 Build and deploy the sanitized public commercial MCP service (alpha-mcp-public) under dedicated zero-privilege SA eloquent-mcp-public with fail-closed Cloudflare Edge origin lock
# MECHANISM_OF_ACTION: Runs commercial_mcp_server.py --selftest and test_commercial_sanitization.py, stages a minimal build context containing ONLY commercial_mcp_server.py + Dockerfile, reads eloquent-edge-shared-secret into RAM from Secret Manager, deploys alpha-mcp-public to Cloud Run us-east1 (--min-instances 0, zero GCS/BQ/owner IAM roles), and verifies direct 403 block + authenticated 200 initialize
# ==============================================================================
[CmdletBinding()]
param(
    [string]$Project = "project-31f97d8a-b7dd-449b-b4d",
    [string]$Region  = "us-east1",
    [string]$Service = "alpha-mcp-public",
    [string]$ServiceAccount = "eloquent-mcp-public@project-31f97d8a-b7dd-449b-b4d.iam.gserviceaccount.com"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONDONTWRITEBYTECODE = "1"

Write-Host "[1/4] Running commercial --selftest and sanitization security tests..." -ForegroundColor Cyan
python -B (Join-Path $repoRoot "commercial_mcp_server.py") --selftest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -B -m unittest discover -s (Join-Path $repoRoot "tests") -p "test_commercial_*.py"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/4] Preparing air-gapped build context (zero owner files)..." -ForegroundColor Cyan
$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) ("eloquent-commercial-build-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $repoRoot "commercial_mcp_server.py") -Destination (Join-Path $stageDir "commercial_mcp_server.py") -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot "Dockerfile.commercial") -Destination (Join-Path $stageDir "Dockerfile") -Force

    $edgeSecret = ((& gcloud secrets versions access latest --secret=eloquent-edge-shared-secret --project=$Project) | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($edgeSecret)) { throw "eloquent-edge-shared-secret is empty" }

    Write-Host "[3/4] Deploying $Service to Cloud Run ($Region, zero-privilege SA)..." -ForegroundColor Cyan
    & gcloud run deploy $Service `
        --source $stageDir `
        --region $Region `
        --project $Project `
        --service-account $ServiceAccount `
        --min-instances 0 `
        --max-instances 5 `
        --memory 512Mi `
        --cpu 1 `
        --cpu-throttling `
        --cpu-boost `
        --allow-unauthenticated `
        --set-env-vars "ELOQUENT_EDGE_SHARED_SECRET=$edgeSecret" `
        --quiet
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $serviceUrl = ((& gcloud run services describe $Service --region=$Region --project=$Project --format="value(status.url)") | Out-String).Trim()
    Write-Host "[4/4] Verifying direct-origin 403 lock & edge-signed 200 MCP initialize at $serviceUrl ..." -ForegroundColor Cyan
    $env:COMMERCIAL_PROBE_URL = $serviceUrl
    $env:COMMERCIAL_PROBE_SECRET = $edgeSecret
    @'
import json, os, urllib.error, urllib.request
base = os.environ["COMMERCIAL_PROBE_URL"].rstrip("/")
sec = os.environ["COMMERCIAL_PROBE_SECRET"]

# 1. /health -> 200
h = json.loads(urllib.request.urlopen(base + "/health", timeout=15).read())
assert h["status"] == "ONLINE" and h["zero_disk_vault"] is True and h["runtime_parity_ok"] is True, h
print(f"PROBE_HEALTH: 200 server={h['server']} tools={h['tools_count']} runtime_parity_ok={h['runtime_parity_ok']}")

# 2. Direct POST /mcp without edge secret -> 403 (fail closed)
req_no_sec = urllib.request.Request(
    base + "/mcp",
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    urllib.request.urlopen(req_no_sec, timeout=15)
    raise AssertionError("Expected 403 on direct origin call without edge secret")
except urllib.error.HTTPError as e:
    assert e.code == 403, f"Expected 403, got {e.code}"
    print("PROBE_DIRECT_BLOCK: 403 edge_gateway_required=True")

# 3. Edge-signed POST /mcp initialize -> 200
req_ok = urllib.request.Request(
    base + "/mcp",
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2026-07-28", "capabilities": {}, "clientInfo": {"name": "deploy-probe", "version": "1.0"}}}).encode(),
    headers={"Content-Type": "application/json", "X-Eloquent-Edge-Secret": sec, "X-Eloquent-Tier": "pro"},
    method="POST",
)
res = json.loads(urllib.request.urlopen(req_ok, timeout=15).read())
assert res["result"]["protocolVersion"] == "2026-07-28" and res["result"]["serverInfo"]["name"] == "eloquent-mcp-commercial"
print("PROBE_EDGE_INIT: 200 protocol=2026-07-28")
'@ | python -
    $pExit = $LASTEXITCODE
    Remove-Item Env:COMMERCIAL_PROBE_URL -ErrorAction SilentlyContinue
    Remove-Item Env:COMMERCIAL_PROBE_SECRET -ErrorAction SilentlyContinue
    if ($pExit -ne 0) { exit $pExit }

    Write-Host "COMMERCIAL_DEPLOY_COMPLETE: origin_url=$serviceUrl" -ForegroundColor Green
} finally {
    if (Test-Path $stageDir) { Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue }
}
exit 0
