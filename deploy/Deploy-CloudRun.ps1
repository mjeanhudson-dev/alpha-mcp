# ==============================================================================
# LABEL:               One-Command Standard-Practice Cloud Run Deploy & Verify
# USE:                 Run local tests, optionally store Google OAuth Web Client credentials and allowlist email in Secret Manager, deploy alpha-mcp to Cloud Run, and probe live OAuth/MCP endpoints.
# MECHANISM_OF_ACTION: Runs alpha_mcp_server.py --selftest + unittest discovery, manages Secret Manager secrets safely under PS 5.1 stderr semantics (relying on project-level secretAccessor for aether-mcp-worker), invokes gcloud run deploy --source, and verifies live HTTPS endpoints.
# ==============================================================================
[CmdletBinding()]
param(
    [string]$Project = "project-31f97d8a-b7dd-449b-b4d",
    [string]$Region = "us-east1",
    [string]$Service = "alpha-mcp",
    [string]$ServiceAccount = "aether-mcp-worker@project-31f97d8a-b7dd-449b-b4d.iam.gserviceaccount.com",
    [string]$AllowedEmails = "",
    [switch]$SetGoogleOAuth,
    [switch]$SkipLocalTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom

function Invoke-Gcloud {
    param([Parameter(Mandatory = $true)][string[]]$Args)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & gcloud @Args
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Test-GcpSecretExists {
    param([Parameter(Mandatory = $true)][string]$SecretName)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & gcloud secrets describe $SecretName --project=$Project 1>$null 2>$null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Set-GcpSecretValue {
    param(
        [Parameter(Mandatory = $true)][string]$SecretName,
        [Parameter(Mandatory = $true)][string]$Value
    )
    if (-not (Test-GcpSecretExists -SecretName $SecretName)) {
        $code = Invoke-Gcloud -Args @("secrets", "create", $SecretName, "--replication-policy=automatic", "--project=$Project", "--quiet")
        if ($code -ne 0) { throw "Failed creating secret $SecretName (exit=$code)" }
    }

    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, $Value.Trim(), $utf8NoBom)
        $code = Invoke-Gcloud -Args @("secrets", "versions", "add", $SecretName, "--data-file=$tmp", "--project=$Project", "--quiet")
        if ($code -ne 0) { throw "Failed adding secret version for $SecretName (exit=$code)" }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# 1. Local verification gate
if (-not $SkipLocalTests) {
    Write-Host "[1/4] Running local --selftest and full E2E unittest suite..." -ForegroundColor Cyan
    $env:PYTHONDONTWRITEBYTECODE = "1"
    python (Join-Path $repoRoot "alpha_mcp_server.py") --selftest
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -m unittest discover -s (Join-Path $repoRoot "tests") -p "test_*.py" -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "[1/4] Local tests skipped (-SkipLocalTests)." -ForegroundColor Yellow
}

# 2. Optional interactive Google OAuth secret provisioning (never printed to stdout)
if ($SetGoogleOAuth) {
    Write-Host "[2/4] Storing Google OAuth Web Client credentials in Secret Manager..." -ForegroundColor Cyan
    $hasExistingCid = Test-GcpSecretExists -SecretName "alpha-mcp-google-client-id"
    if ($hasExistingCid) {
        $cid = (Read-Host "Enter Google OAuth Client ID (press Enter to keep existing alpha-mcp-google-client-id)").Trim()
        if ($cid) { Set-GcpSecretValue -SecretName "alpha-mcp-google-client-id" -Value $cid }
    } else {
        $cid = (Read-Host "Enter Google OAuth Client ID (ends with .apps.googleusercontent.com)").Trim()
        if (-not $cid) { throw "Google OAuth Client ID cannot be empty." }
        Set-GcpSecretValue -SecretName "alpha-mcp-google-client-id" -Value $cid
    }

    $secSecure = Read-Host "Enter Google OAuth Client Secret (input hidden)" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secSecure)
    try {
        $csec = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr).Trim()
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if (-not $csec) { throw "Google OAuth Client Secret cannot be empty." }

    $hasExistingEmails = Test-GcpSecretExists -SecretName "alpha-mcp-allowed-emails"
    if ([string]::IsNullOrWhiteSpace($AllowedEmails)) {
        if ($hasExistingEmails) {
            $AllowedEmails = (Read-Host "Enter allowed Google email(s) (press Enter to keep existing alpha-mcp-allowed-emails)").Trim()
        } else {
            $AllowedEmails = (Read-Host "Enter allowed Google email(s) (comma-separated, e.g. eloquent@eloquentwin.com)").Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($AllowedEmails) -and -not $hasExistingEmails) {
        throw "AllowedEmails cannot be empty when enabling Google OAuth."
    }

    Set-GcpSecretValue -SecretName "alpha-mcp-google-client-secret" -Value $csec
    if (-not [string]::IsNullOrWhiteSpace($AllowedEmails)) {
        Set-GcpSecretValue -SecretName "alpha-mcp-allowed-emails" -Value $AllowedEmails
    }
    $cid = $null
    $csec = $null
    Write-Host "Stored Google OAuth secrets cleanly (covered by project-level secretAccessor on $ServiceAccount)." -ForegroundColor Green
} else {
    Write-Host "[2/4] Checking existing Secret Manager bindings..." -ForegroundColor Cyan
}

# 3. Assemble Cloud Run secrets & env args and deploy
if (-not (Test-GcpSecretExists -SecretName "alpha-mcp-signing-secret")) {
    Write-Host "[2b/4] Minting persistent alpha-mcp-signing-secret in Secret Manager..." -ForegroundColor Cyan
    $newSig = (python -c "import secrets; print(secrets.token_urlsafe(32))").Trim()
    Set-GcpSecretValue -SecretName "alpha-mcp-signing-secret" -Value $newSig
    $newSig = $null
}

$hasGoogleClientId = Test-GcpSecretExists -SecretName "alpha-mcp-google-client-id"
$hasGoogleClientSecret = Test-GcpSecretExists -SecretName "alpha-mcp-google-client-secret"
$hasAllowedEmailsSecret = Test-GcpSecretExists -SecretName "alpha-mcp-allowed-emails"
$googleReady = ($hasGoogleClientId -and $hasGoogleClientSecret -and ($hasAllowedEmailsSecret -or -not [string]::IsNullOrWhiteSpace($AllowedEmails)))

$secretsArg = "ALPHA_MCP_BEARER_TOKEN=alpha-mcp-bearer-token:latest,ALPHA_MCP_SIGNING_SECRET=alpha-mcp-signing-secret:latest"
$envVarsList = @(
    "GOOGLE_CLOUD_PROJECT=$Project",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=$ServiceAccount",
    "NEXUS_FLASH_SHUNT=1",
    "NEXUS_VERTEX_MODEL=gemini-4-carbon",
    "ALPHA_MCP_GCS_VAULT_URI=gs://alpha-mcp-vault-907374614316/stage0/latest",
    "ALPHA_MCP_OAUTH_DEFAULT_MODE=hybrid"
)
$deployArgs = @(
    "run", "deploy", $Service,
    "--source", $repoRoot,
    "--region", $Region,
    "--project", $Project,
    "--service-account", $ServiceAccount,
    "--min-instances", "0",
    "--max-instances", "2",
    "--memory", "512Mi",
    "--cpu", "1",
    "--cpu-throttling",
    "--cpu-boost",
    "--allow-unauthenticated",
    "--quiet"
)

if ($googleReady) {
    $secretsArg += ",GOOGLE_OAUTH_CLIENT_ID=alpha-mcp-google-client-id:latest,GOOGLE_OAUTH_CLIENT_SECRET=alpha-mcp-google-client-secret:latest"
    if (-not [string]::IsNullOrWhiteSpace($AllowedEmails)) {
        $envVarsList += "ALPHA_MCP_ALLOWED_EMAILS=$AllowedEmails"
    } elseif ($hasAllowedEmailsSecret) {
        $secretsArg += ",ALPHA_MCP_ALLOWED_EMAILS=alpha-mcp-allowed-emails:latest"
    }
}
$deployArgs += @("--set-env-vars", ($envVarsList -join ","))
$deployArgs += @("--set-secrets", $secretsArg)

Write-Host "[3/4] Deploying $Service to Cloud Run ($Region, google_signin=$googleReady)..." -ForegroundColor Cyan
$deployCode = Invoke-Gcloud -Args $deployArgs
if ($deployCode -ne 0) { exit $deployCode }

$prevErr = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$serviceUrl = ((& gcloud run services describe $Service --region=$Region --project=$Project --format="value(status.url)") | Out-String).Trim()
$ErrorActionPreference = $prevErr

$probeBase = "https://alpha-mcp-mxnmqsr7gq-ue.a.run.app"
try {
    Invoke-WebRequest -Uri "$probeBase/health" -UseBasicParsing -TimeoutSec 5 | Out-Null
} catch {
    $probeBase = $serviceUrl
}

# 4. Live end-to-end verification probes (never printing secret values)
Write-Host "[4/4] Running live HTTP probes against $probeBase ..." -ForegroundColor Cyan
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:ALPHA_PROBE_BASE = $probeBase
@'
import base64
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["ALPHA_PROBE_BASE"].rstrip("/")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def call(path, method="GET", headers=None, body=None, follow=True):
    req = urllib.request.Request(BASE + path, data=body, method=method, headers=headers or {})
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode("utf-8", "replace")
        finally:
            e.close()

st, _, body = call("/health")
health = json.loads(body)
assert st == 200 and health.get("status") == "ONLINE", (st, health)
mode = health.get("oauth_login_mode")
print(f"PROBE_HEALTH: status={st} oauth_login_mode={mode}")

st, hdrs, _ = call("/mcp", method="HEAD")
assert st == 401 and "oauth-protected-resource" in hdrs.get("www-authenticate", ""), (st, hdrs)
print(f"PROBE_HEAD_MCP: status={st}")

dcr_ok = json.dumps({
    "client_name": "Deploy Probe Client",
    "redirect_uris": ["https://oauth-redirect.googleusercontent.com/r/probe"],
    "token_endpoint_auth_method": "client_secret_basic",
}).encode("utf-8")
st, _, body = call("/oauth/register", method="POST", headers={"Content-Type": "application/json"}, body=dcr_ok)
reg = json.loads(body)
assert st == 201 and reg.get("client_id", "").startswith("alpha-client-"), (st, reg)
cid = reg["client_id"]
print(f"PROBE_DCR_VALID: status={st} client_id={cid} secret=[REDACTED]")

st, _, body = call("/oauth/register", method="POST", headers={"Content-Type": "application/json"}, body=b'{"client_name":"bad"}')
assert st == 400 and json.loads(body).get("error") == "invalid_client_metadata", st
print(f"PROBE_DCR_INVALID: status={st}")

challenge = base64.urlsafe_b64encode(hashlib.sha256(b"deploy-probe-pkce").digest()).rstrip(b"=").decode("ascii")
qs = urllib.parse.urlencode({
    "response_type": "code",
    "client_id": cid,
    "redirect_uri": "https://oauth-redirect.googleusercontent.com/r/probe",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "scope": "mcp:read mcp:tools",
    "state": "deploy-probe-state",
})
st, hdrs, body = call(f"/oauth/authorize?{qs}", headers={"Accept": "text/html"}, follow=False)
if mode == "google_signin":
    loc = hdrs.get("location", "")
    assert st == 302 and loc.startswith("https://accounts.google.com/o/oauth2/v2/auth"), (st, loc)
    assert "alpha_oauth_csrf=" in hdrs.get("set-cookie", ""), hdrs
    print(f"PROBE_AUTHORIZE_GOOGLE: status={st} redirect_host=accounts.google.com")
else:
    csp = hdrs.get("content-security-policy", "")
    assert st == 200 and "form-action" not in csp and "Authorize Alpha MCP Access" in body, (st, csp)
    print(f"PROBE_AUTHORIZE_CONSENT: status={st} csp_no_form_action=True")
'@ | python -
$probeExit = $LASTEXITCODE
Remove-Item Env:ALPHA_PROBE_BASE -ErrorAction SilentlyContinue
if ($probeExit -ne 0) { exit $probeExit }

Write-Host "`nDEPLOY_COMPLETE: mcp_url=$probeBase/mcp" -ForegroundColor Green
Write-Host "GOOGLE_OAUTH_CALLBACK_URI=$probeBase/oauth/google/callback"
exit 0
