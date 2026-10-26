#Requires -Version 5.1
<#
.SYNOPSIS
    Development mode: API on 127.0.0.1:8765 in a new window, Vite dev server (hot reload) on :5173 here.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Start-Process -FilePath 'uv' -ArgumentList @('run', 'sentinel-server', 'serve') -WorkingDirectory $repo
Set-Location (Join-Path $repo 'web')
if (-not (Test-Path node_modules)) { npm install }
npm run dev
