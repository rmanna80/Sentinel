#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the dashboard (web/) and installs it into the server's static folder.
.DESCRIPTION
    Runs npm ci (or npm install when there is no lock file), npm run build, then replaces
    packages\server\src\sentinel_server\static with the contents of web\dist.
    Needs Node.js LTS (22.22 or newer): winget install --id OpenJS.NodeJS.LTS -e
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$web = Join-Path $repo 'web'
$static = Join-Path $repo 'packages\server\src\sentinel_server\static'

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'npm was not found. Install Node.js LTS (winget install --id OpenJS.NodeJS.LTS -e), then open a new PowerShell window.'
}

Push-Location $web
try {
    if (Test-Path (Join-Path $web 'package-lock.json')) {
        npm ci --no-audit --no-fund
    } else {
        npm install --no-audit --no-fund
    }
    if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }

    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$dist = Join-Path $web 'dist'
if (-not (Test-Path (Join-Path $dist 'index.html'))) { throw 'The build produced no dist\index.html' }

if (Test-Path $static) { Remove-Item -Recurse -Force $static }
New-Item -ItemType Directory -Path $static | Out-Null
Copy-Item -Path (Join-Path $dist '*') -Destination $static -Recurse -Force
Write-Host "Dashboard installed in $static" -ForegroundColor Green
exit 0
