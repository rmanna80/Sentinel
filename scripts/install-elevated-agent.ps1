#Requires -Version 5.1
<#
.SYNOPSIS
    Installs a protected copy of the Sentinel agent for elevated scans. Run once, as administrator,
    and again after each Sentinel update.
.DESCRIPTION
    An elevated scan must not run code that a standard user (or malware running as that user) can change.
    The repository, its .venv and uv's caches are all user-writable, so elevated scans never use them.
    This script builds the agent from the repository and installs it, with its own Python, into
    "C:\Program Files\Sentinel", which only administrators can modify. scripts\elevated-scan.ps1 then
    launches that copy and nothing else.

    This step itself runs as administrator and installs the code that is in the repository right now,
    so run it right after downloading or updating Sentinel, and check that nothing has modified the code.
#>
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an administrator PowerShell window (right-click PowerShell > Run as administrator).'
}

$repo = Split-Path -Parent $PSScriptRoot
# Known-folder lookups, not environment variables: a per-user variable could point these elsewhere.
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$dest = Join-Path $programFiles 'Sentinel'
$uv = (Get-Command uv -ErrorAction Stop).Source

if (Get-Command git -ErrorAction SilentlyContinue) {
    $changes = & git -C $repo status --porcelain -- packages 2>$null
    if ($LASTEXITCODE -eq 0 -and $changes) {
        Write-Warning 'The agent source has uncommitted changes:'
        $changes | ForEach-Object { Write-Warning "  $_" }
        $answer = Read-Host 'Install these changes into the protected copy anyway? (yes/no)'
        if ($answer -ne 'yes') { throw 'Stopped. Review the changes (git diff) first.' }
    }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("sentinel-elevated-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$staging = Join-Path $dest 'staging'
try {
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
    New-Item -ItemType Directory -Path $staging | Out-Null

    # A fresh, admin-only cache and Python: nothing from the user's uv cache is reused.
    $env:UV_CACHE_DIR = Join-Path $staging 'uv-cache'
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $staging 'python'
    $env:UV_NO_CONFIG = '1'

    Write-Host 'Installing Python 3.12 for the protected agent...' -ForegroundColor Cyan
    & $uv python install 3.12
    if ($LASTEXITCODE -ne 0) { throw 'uv python install failed' }

    Write-Host 'Building the agent from the repository...' -ForegroundColor Cyan
    Push-Location $repo
    try {
        foreach ($pkg in @('sentinel-core', 'sentinel-agent')) {
            & $uv build --package $pkg --wheel --out-dir $work
            if ($LASTEXITCODE -ne 0) { throw "uv build $pkg failed" }
        }
        $requirements = Join-Path $work 'requirements.txt'
        & $uv export --package sentinel-agent --frozen --no-dev --no-hashes --no-emit-workspace --output-file $requirements
        if ($LASTEXITCODE -ne 0) { throw 'uv export failed' }
    } finally {
        Pop-Location
    }

    Write-Host 'Creating the protected environment...' -ForegroundColor Cyan
    $venv = Join-Path $staging 'agent'
    & $uv venv $venv --python 3.12 --managed-python
    if ($LASTEXITCODE -ne 0) { throw 'uv venv failed' }
    $python = Join-Path $venv 'Scripts\python.exe'
    $wheels = @(Get-ChildItem -Path $work -Filter '*.whl' | ForEach-Object { $_.FullName })
    & $uv pip install --python $python -r $requirements @wheels
    if ($LASTEXITCODE -ne 0) { throw 'installing the agent into the protected environment failed' }

    # -I: isolated mode. Ignores PYTHONPATH and other PYTHON* variables and the user site-packages folder.
    $launcher = @'
$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot 'agent\Scripts\python.exe'
Write-Host 'Running elevated scan jobs from the protected Sentinel agent (read-only). This window closes when done.' -ForegroundColor Cyan
& $python -I -m sentinel_agent run --elevated --idle-exit 30
Start-Sleep -Seconds 3
'@
    Set-Content -Path (Join-Path $staging 'elevated-run.ps1') -Value $launcher -Encoding UTF8

    Remove-Item -Recurse -Force $env:UV_CACHE_DIR

    # Swap the new copy in only after everything succeeded.
    foreach ($name in @('agent', 'python', 'elevated-run.ps1')) {
        $old = Join-Path $dest $name
        if (Test-Path $old) { Remove-Item -Recurse -Force $old }
        Move-Item -Path (Join-Path $staging $name) -Destination $old
    }
    Remove-Item -Recurse -Force $staging
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

# Program Files grants standard users read and execute only; confirm nothing loosened it.
$acl = Get-Acl $dest
$writable = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    ($_.IdentityReference -match 'Users|Everyone|Authenticated Users|INTERACTIVE') -and
    ($_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles|AppendData')
}
if ($writable) {
    Write-Warning "Standard users can write to $dest. Fix its permissions before running elevated scans."
} else {
    Write-Host "Protected agent installed in $dest (administrators only can change it)." -ForegroundColor Green
}
Write-Host 'Queue an elevated scan in the dashboard, then run scripts\elevated-scan.ps1 from a normal window.'
