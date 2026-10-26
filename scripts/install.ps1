#Requires -Version 5.1
<#
.SYNOPSIS
    Installs Sentinel's Python environment, builds the dashboard and prepares the database.
.DESCRIPTION
    Run from a normal (not administrator) PowerShell window inside the repository folder:
        powershell -ExecutionPolicy Bypass -File scripts\install.ps1
    Needs uv (winget install --id astral-sh.uv -e) and Node.js LTS for the dashboard build.
#>
param(
    [switch]$SkipWeb
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if ($repo -match '\\OneDrive') {
    Write-Warning ("This folder is inside OneDrive ($repo). Move the repository to a local folder such as C:\dev\sentinel: " +
        "OneDrive sync can replace files mid-build and corrupt a live database.")
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv is not installed. Run: winget install --id astral-sh.uv -e   then open a new PowerShell window and run this again."
}

Write-Host "Installing Python 3.12 (managed by uv) and dependencies..." -ForegroundColor Cyan
uv python install 3.12
if ($LASTEXITCODE -ne 0) { throw "uv python install failed" }
uv sync --locked
if ($LASTEXITCODE -ne 0) { throw "uv sync failed" }

if (-not $SkipWeb) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        throw "npm was not found. Install Node.js LTS (winget install --id OpenJS.NodeJS.LTS -e) or rerun with -SkipWeb."
    }
    & (Join-Path $PSScriptRoot 'build-web.ps1')
    if ($LASTEXITCODE -ne 0) { throw "dashboard build failed" }
}

Write-Host "Preparing the database..." -ForegroundColor Cyan
uv run sentinel-server migrate
if ($LASTEXITCODE -ne 0) { throw "database migration failed" }

Write-Host ""
Write-Host "Sentinel is installed." -ForegroundColor Green
Write-Host "  1. Start the server:  powershell -ExecutionPolicy Bypass -File scripts\start-server.ps1"
Write-Host "  2. Open http://127.0.0.1:8765 and finish setup with the token the server prints."
Write-Host "  3. In the dashboard, Devices > Enroll a device, then run the command it shows."
Write-Host "  4. Start the agent:   powershell -ExecutionPolicy Bypass -File scripts\start-agent.ps1"
