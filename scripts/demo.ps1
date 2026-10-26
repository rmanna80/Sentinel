#Requires -Version 5.1
<#
.SYNOPSIS
    Runs a self-contained DEMO: a separate server in demo mode on port 8766, answered by an agent that
    replays hand-written fixture data instead of reading this machine.
.DESCRIPTION
    Demo data is badged as such everywhere in the dashboard and kept in its own data folder, so it never
    mixes with your real results. Production mode (the normal server) refuses fixture data outright.
#>
param(
    [ValidateSet('windows', 'linux')][string]$Fixture = 'windows',
    [int]$Port = 8766
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$env:SENTINEL_MODE = 'demo'
$env:SENTINEL_PORT = "$Port"
$env:SENTINEL_DATA_DIR = Join-Path $env:LOCALAPPDATA 'Sentinel\demo-server'
$env:SENTINEL_AGENT_HOME = Join-Path $env:LOCALAPPDATA 'Sentinel\demo-agent'
$fixtureFile = if ($Fixture -eq 'windows') { 'packages\agent\tests\fixtures\windows-home-demo.json' } else { 'packages\agent\tests\fixtures\linux-pi-demo.json' }

Write-Host "Starting the demo server on http://127.0.0.1:$Port ..." -ForegroundColor Cyan
$server = Start-Process -FilePath 'uv' -ArgumentList @('run', 'sentinel-server', 'serve', '--port', "$Port", '--mode', 'demo') `
    -WorkingDirectory $repo -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 6

$code = (uv run sentinel-server create-enrollment-code --port $Port --mode demo | Select-Object -Last 1).Trim()
uv run sentinel-agent enroll --server "http://127.0.0.1:$Port" --code $code
Write-Host ""
Write-Host "Open http://127.0.0.1:$Port, finish setup with the token shown in the server window" -ForegroundColor Green
Write-Host "(also in $env:SENTINEL_DATA_DIR\setup-token.txt), then queue scans. Press Ctrl+C here to stop the demo agent."
try {
    uv run sentinel-agent run --fixtures $fixtureFile
} finally {
    Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
}
