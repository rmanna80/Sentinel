#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the Sentinel server on http://127.0.0.1:8765 (this machine only).
#>
param(
    [int]$Port = 8765
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
uv run sentinel-server serve --port $Port
