# ==============================================================================
# LABEL:               Start Alpha MCP Sovereign Dual-Modality Edge Server
# USE:                 Launch alpha_mcp_server.py in authenticated Streamable HTTP mode on loopback, verify /health reports ONLINE, and optionally bind a permanent Cloudflare Named Tunnel.
# MECHANISM_OF_ACTION: Validates ALPHA_MCP_BEARER_TOKEN (fail-closed refusal if blank), resolves alpha_mcp_server.py and vault path relative to repository root, starts Python child process with --transport http --host 127.0.0.1 --port <Port> --require-auth, polls http://127.0.0.1:<Port>/health until ONLINE, and optionally execs cloudflared tunnel run --url http://127.0.0.1:<Port> <TunnelName> with guaranteed child-process teardown on exit.
# ==============================================================================
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8000,

    [string]$TunnelName = "",

    [string]$VaultDb = "./mcp_alpha_vault.sqlite3"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 1. Fail-Closed Authentication Gate (never expose an unauthenticated edge endpoint)
if ([string]::IsNullOrWhiteSpace($env:ALPHA_MCP_BEARER_TOKEN)) {
    [Console]::Error.WriteLine("[ALPHA-EDGE][REFUSED] ALPHA_MCP_BEARER_TOKEN is empty or unset. Set a strong secret in `$env:ALPHA_MCP_BEARER_TOKEN before starting the edge HTTP server.")
    exit 1
}

if (-not [string]::IsNullOrWhiteSpace($TunnelName) -and [string]::IsNullOrWhiteSpace($env:ALPHA_MCP_OAUTH_SECRET)) {
    Write-Warning "ALPHA_MCP_OAUTH_SECRET is unset; /oauth/authorize will require ALPHA_MCP_BEARER_TOKEN when accessed over the tunnel."
}

# 2. Resolve repository root, Python runtime, and server entrypoint
$repoRoot = Split-Path -Parent $PSScriptRoot
$serverScript = Join-Path $repoRoot "alpha_mcp_server.py"
if (-not (Test-Path -LiteralPath $serverScript)) {
    [Console]::Error.WriteLine("[ALPHA-EDGE][ERROR] Server entrypoint not found: $serverScript")
    exit 1
}

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $pythonCmd) {
    [Console]::Error.WriteLine("[ALPHA-EDGE][ERROR] Python 3.10+ runtime ('python' or 'python3') was not found on PATH.")
    exit 1
}

# Resolve VaultDb relative to current working directory or repo root
if ([System.IO.Path]::IsPathRooted($VaultDb)) {
    $resolvedVault = $VaultDb
} elseif (Test-Path -LiteralPath $VaultDb) {
    $resolvedVault = (Resolve-Path -LiteralPath $VaultDb).Path
} else {
    $resolvedVault = Join-Path $repoRoot $VaultDb
}
$env:ALPHA_MCP_VAULT_DB = $resolvedVault

if (-not (Test-Path -LiteralPath $resolvedVault)) {
    Write-Warning "Vault file not found at '$VaultDb'. Run 'python ./mcp_carbon_ingest.py ingest --roots ./examples/sample_workspace --db $VaultDb' to populate FTS5 search."
}

# 3. Validate cloudflared availability before launching child server if -TunnelName is requested
$cloudflaredCmd = $null
if (-not [string]::IsNullOrWhiteSpace($TunnelName)) {
    $cloudflaredCmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    if (-not $cloudflaredCmd) {
        [Console]::Error.WriteLine("[ALPHA-EDGE][ERROR] cloudflared CLI not found on PATH. Install Cloudflare Tunnel (winget install Cloudflare.cloudflared) before passing -TunnelName '$TunnelName'.")
        exit 1
    }
}

# 4. Launch Streamable HTTP MCP server on loopback with --require-auth
$serverArgs = @(
    $serverScript,
    "--transport", "http",
    "--host", "127.0.0.1",
    "--port", "$Port",
    "--require-auth"
)

Write-Host "[ALPHA-EDGE] Starting Streamable HTTP server on http://127.0.0.1:$Port (--require-auth)..."
$serverProc = Start-Process -FilePath $pythonCmd.Source -ArgumentList $serverArgs -WorkingDirectory $repoRoot -NoNewWindow -PassThru

$healthUrl = "http://127.0.0.1:$Port/health"
$onlinePayload = $null

try {
    # 5. Poll /health until status == ONLINE (max 15 seconds)
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        if ($serverProc.HasExited) {
            throw "alpha_mcp_server.py exited prematurely with code $($serverProc.ExitCode) before /health became ONLINE."
        }
        try {
            $resp = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 2
            if ($resp -and $resp.status -eq "ONLINE") {
                $onlinePayload = $resp
                break
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }

    if (-not $onlinePayload) {
        throw "Timed out waiting for $healthUrl to report status=ONLINE."
    }

    Write-Host "[ALPHA-EDGE] ONLINE | pid=$($serverProc.Id) version=$($onlinePayload.version) tools=$($onlinePayload.tools_count) endpoint=http://127.0.0.1:$Port/mcp"
    Write-Host "[ALPHA-EDGE] Discovery: http://127.0.0.1:$Port/.well-known/agent-card.json | Health: $healthUrl"

    # 6. Attach Named Cloudflare Tunnel if requested, otherwise hold foreground until interrupted
    if ($cloudflaredCmd) {
        Write-Host "[ALPHA-EDGE] Binding Cloudflare Named Tunnel '$TunnelName' -> http://127.0.0.1:$Port ..."
        $ErrorActionPreference = "Continue"
        & $cloudflaredCmd.Source tunnel run --url "http://127.0.0.1:$Port" $TunnelName
        exit $LASTEXITCODE
    } else {
        Write-Host "[ALPHA-EDGE] Running in local authenticated HTTP mode (no tunnel). Press Ctrl+C to stop."
        Wait-Process -Id $serverProc.Id
    }
} finally {
    if ($serverProc -and -not $serverProc.HasExited) {
        Write-Host "[ALPHA-EDGE] Stopping alpha_mcp_server.py (PID $($serverProc.Id))..."
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
}
