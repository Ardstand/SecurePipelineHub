# scripts/local_scan.ps1
# Clones the target repo and runs the full security pipeline across
# all commits (or a limited range). ZAP runs only on the latest commit.
#
# Usage:
#   .\scripts\local_scan.ps1                    # scan all commits
#   .\scripts\local_scan.ps1 -Limit 10          # scan latest 10 commits
#   .\scripts\local_scan.ps1 -UntilSha abc123   # scan until this SHA
#   .\scripts\local_scan.ps1 -SkipZap           # skip ZAP entirely
#   .\scripts\local_scan.ps1 -Force             # re-scan already scanned commits

param(
    [int]$Limit = 0,
    [string]$UntilSha = "",
    [switch]$SkipZap,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Info($msg)  { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "[OK]    $msg" -ForegroundColor Green }
function Warn($msg)  { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Err($msg)   { Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Head($msg)  { Write-Host "`n$('='*55)`n$msg`n$('='*55)" -ForegroundColor White }

$SCRIPT_DIR   = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent $SCRIPT_DIR
$ENV_FILE     = Join-Path $PROJECT_ROOT ".env"
$REPO_CACHE   = Join-Path $PROJECT_ROOT ".repo_cache"
$APP_PORT     = 3000
$ZAP_REPORT   = "zap-report.json"

Head "SECUREPIPELINEHUB - LOCAL SCAN"

# ── Load .env ─────────────────────────────────────────────────────────────────
if (Test-Path $ENV_FILE) {
    Info "Loading .env"
    Get-Content $ENV_FILE | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $k = $matches[1].Trim()
            $v = $matches[2].Trim().Trim('"').Trim("'")
            [System.Environment]::SetEnvironmentVariable($k, $v, "Process")
        }
    }
    Ok ".env loaded"
} else {
    Warn "No .env found at $ENV_FILE"
}

$TARGET_REPO_URL = [System.Environment]::GetEnvironmentVariable("TARGET_REPO_URL")
if (-not $TARGET_REPO_URL) {
    Err "TARGET_REPO_URL not set in .env"
    exit 1
}

# ── Step 1: Clone or update target repo ───────────────────────────────────────
Head "Step 1 - Clone / update target repo"

if (Test-Path (Join-Path $REPO_CACHE ".git")) {
    Info "Updating existing clone at $REPO_CACHE"
    $ErrorActionPreference = "SilentlyContinue"
    git -C $REPO_CACHE fetch --all --quiet 2>&1 | Out-Null
    git -C $REPO_CACHE reset --hard origin/HEAD --quiet 2>&1 | Out-Null
    $ErrorActionPreference = "Stop"
    Ok "Updated"
} else {
    Info "Cloning $TARGET_REPO_URL"
    git clone $TARGET_REPO_URL $REPO_CACHE
    Ok "Cloned"
}

# ── Step 2: Build commit list ─────────────────────────────────────────────────
Head "Step 2 - Build commit list"

# Use absolute path and push/pop location to guarantee correct repo
$gitLogArgs = "log --format=%H"
if ($Limit -gt 0) { $gitLogArgs += " -n $Limit" }

Push-Location $REPO_CACHE
$allCommits = Invoke-Expression "git $gitLogArgs" 2>&1 |
    Where-Object { $_ -match '^[0-9a-f]{40}$' }
Pop-Location

if ($UntilSha -ne "") {
    $trimmed = @()
    foreach ($sha in $allCommits) {
        $trimmed += $sha
        if ($sha.StartsWith($UntilSha)) { break }
    }
    $allCommits = $trimmed
    Info "Scanning until $($UntilSha.Substring(0,[Math]::Min(8,$UntilSha.Length))) - $($allCommits.Count) commits"
} else {
    $limitLabel = if ($Limit -gt 0) { "(limit: $Limit)" } else { "(all commits)" }
    Info "Commits to scan: $($allCommits.Count) $limitLabel"
}

if ($allCommits.Count -eq 0) {
    Err "No commits found"
    exit 1
}

$HEAD_SHA   = $allCommits[0]
$HEAD_SHORT = $HEAD_SHA.Substring(0, 8)
Info "Latest commit: $HEAD_SHORT"

# ── Step 4: Scan commits ───────────────────────────────────────────────────────
Head "Step 3 - Pipeline scan ($($allCommits.Count) commits)"

Set-Location $PROJECT_ROOT

$scanned = 0
$skipped = 0
$errors  = 0
$blocked = @()

for ($i = 0; $i -lt $allCommits.Count; $i++) {
    $sha   = $allCommits[$i]
    $short = $sha.Substring(0, 8)
    $num   = $i + 1

    Write-Host "`n[$num/$($allCommits.Count)] $short" -ForegroundColor White

    $scanArgs = @("processing/commit_scanner.py", "--sha", $sha, "--repo-dir", $REPO_CACHE)
    # --force is handled at the PowerShell level by not skipping already-scanned commits
    # commit_scanner.py does not accept a --force flag

    $ErrorActionPreference = "SilentlyContinue"
    & python @scanArgs
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = "Stop"

    if ($exitCode -eq 0) {
        $scanned++
    } elseif ($exitCode -eq 1) {
        $scanned++
        $blocked += $short
    } else {
        $errors++
        Warn "Scan failed for $short (exit $exitCode)"
    }
}

# Restore HEAD
$ErrorActionPreference = "SilentlyContinue"
& git -C $REPO_CACHE checkout main --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { & git -C $REPO_CACHE checkout master --quiet 2>&1 | Out-Null }
$ErrorActionPreference = "Stop"

# ── Step 3: ZAP on latest commit only ─────────────────────────────────────────
Head "Step 4 - OWASP ZAP (latest commit only)"

$ZAP_OUT = Join-Path $REPO_CACHE $ZAP_REPORT

if ($SkipZap) {
    Info "ZAP skipped (-SkipZap)"
} else {
    $dockerOk = $false
    $ErrorActionPreference = "SilentlyContinue"
    & docker info 2>&1 | Out-Null
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -eq 0) {
        $dockerOk = $true
        Ok "Docker is running"
    } else {
        Warn "Docker not running - skipping ZAP"
    }

    if ($dockerOk -and -not (Test-Path (Join-Path $REPO_CACHE "package.json"))) {
        Warn "No package.json in target repo - skipping ZAP"
        $dockerOk = $false
    }

    if ($dockerOk) {
        # Write app .env
        $APP_ENV_FILE = [System.Environment]::GetEnvironmentVariable("APP_ENV_FILE")
        $envDest = Join-Path $REPO_CACHE ".env"
        if ($APP_ENV_FILE) {
            Info "Writing app .env"
            Set-Content -Path $envDest -Value $APP_ENV_FILE
        } elseif (-not (Test-Path $envDest)) {
            Warn "No APP_ENV_FILE and no .env in target repo - app may fail"
        }

        # Install and start app
        Info "Installing dependencies (npm install)"
        $ErrorActionPreference = "SilentlyContinue"
        & npm install --prefix $REPO_CACHE --quiet 2>&1 | Out-Null
        $ErrorActionPreference = "Stop"

        Info "Starting app on port $APP_PORT"
        $AppProcess = Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c", "cd /d `"$REPO_CACHE`" && npm start" `
            -PassThru -WindowStyle Minimized

        $ready = $false
        Info "Waiting for app..."
        for ($i = 1; $i -le 30; $i++) {
            Start-Sleep -Seconds 2
            $ErrorActionPreference = "SilentlyContinue"
            try {
                $res = Invoke-WebRequest -Uri "http://localhost:$APP_PORT" `
                    -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
                if ($res.StatusCode -lt 500) {
                    $ready = $true
                    Ok "App ready after $($i*2)s (HTTP $($res.StatusCode))"
                    break
                }
            } catch {}
            $ErrorActionPreference = "Stop"
            Write-Host "  Attempt $i/30..."
        }
        $ErrorActionPreference = "Stop"

        if (-not $ready) { Warn "App did not respond - ZAP may get limited results" }

        # Run ZAP
        Info "Running ZAP baseline scan"
        $ErrorActionPreference = "SilentlyContinue"
        & docker run --rm `
            -v "${REPO_CACHE}:/zap/wrk" `
            ghcr.io/zaproxy/zaproxy:stable `
            zap-baseline.py `
            -t "http://host.docker.internal:$APP_PORT" `
            -J $ZAP_REPORT `
            -I
        $ErrorActionPreference = "Stop"

        if (Test-Path $ZAP_OUT) {
            Ok "ZAP report saved"
        } else {
            Warn "ZAP report not found"
        }

        # Stop app
        if ($AppProcess -and -not $AppProcess.HasExited) {
            Info "Stopping app"
            Stop-Process -Id $AppProcess.Id -Force -ErrorAction SilentlyContinue
            $ErrorActionPreference = "SilentlyContinue"
            $portProc = (Get-NetTCPConnection -LocalPort $APP_PORT -ErrorAction SilentlyContinue).OwningProcess
            if ($portProc) { Stop-Process -Id $portProc -Force -ErrorAction SilentlyContinue }
            $ErrorActionPreference = "Stop"
            Ok "App stopped"
        }

        # Re-run pipeline scan for latest commit now that ZAP report exists.
        # First stash the ZAP report, clean the repo, then restore it so
        # git checkout is never blocked by npm install side effects.
        if (Test-Path $ZAP_OUT) {
            Info "Re-scanning latest commit $HEAD_SHORT with ZAP findings..."

            # Copy ZAP report somewhere safe outside the repo
            $ZAP_BACKUP = Join-Path $PROJECT_ROOT "zap-report-backup.json"
            Copy-Item $ZAP_OUT $ZAP_BACKUP -Force

            # Clean local modifications left by npm install
            $ErrorActionPreference = "SilentlyContinue"
            & git -C $REPO_CACHE checkout -- . 2>&1 | Out-Null
            & git -C $REPO_CACHE clean -fd --quiet 2>&1 | Out-Null
            $ErrorActionPreference = "Stop"

            # Restore ZAP report into repo dir for commit_scanner to pick up
            Copy-Item $ZAP_BACKUP $ZAP_OUT -Force

            Set-Location $PROJECT_ROOT
            $ErrorActionPreference = "SilentlyContinue"
            & python processing/commit_scanner.py --sha $HEAD_SHA --repo-dir $REPO_CACHE
            $ErrorActionPreference = "Stop"

            # Clean up backup
            Remove-Item $ZAP_BACKUP -Force -ErrorAction SilentlyContinue
            Ok "Latest commit re-scanned with ZAP findings"
        }
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Head "Done"
Ok   "Scanned : $scanned"
Info "Skipped : $skipped"
if ($errors -gt 0)       { Warn "Errors  : $errors" }
if ($blocked.Count -gt 0) {
    Warn "Blocked : $($blocked.Count) commits had CRITICAL findings"
    $blocked | ForEach-Object { Write-Host "          $_" -ForegroundColor Yellow }
}
Info "Findings saved to data/findings/"
Info "Start Flask to see results: python api/app.py"