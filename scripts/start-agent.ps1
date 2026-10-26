#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the Sentinel agent as the signed-in user (no administrator rights).
.DESCRIPTION
    The agent polls the local server for scan jobs and runs only its registered, read-only checks.
    Checks that need administrator rights are skipped and listed with that reason; run
    scripts\elevated-scan.ps1 when you want them included.
#>
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) {
    Write-Warning "This window is elevated. Run the everyday agent from a normal PowerShell window; use scripts\elevated-scan.ps1 for admin-only checks."
}
uv run sentinel-agent run
