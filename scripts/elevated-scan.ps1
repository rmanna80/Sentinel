#Requires -Version 5.1
<#
.SYNOPSIS
    Runs ONE elevated scan that you queued from the dashboard, then exits.
.DESCRIPTION
    Some checks need administrator rights (BitLocker/Device encryption, Secure Boot, the Security event log).
    Queue an "elevated" scan in the dashboard, then run this script. Windows shows its permission (UAC)
    prompt; the agent takes that one elevated job, runs it read-only, and exits within 30 seconds of idling.
    Sentinel never stores administrator credentials and never elevates itself.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin) {
    Write-Host "Windows will ask for permission to run the elevated scan..." -ForegroundColor Cyan
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $psArgs -Verb RunAs -Wait -PassThru
    exit $proc.ExitCode
}

Set-Location $repo
Write-Host "Running elevated scan jobs (read-only). This window closes when done." -ForegroundColor Cyan
uv run sentinel-agent run --elevated --idle-exit 30
Start-Sleep -Seconds 3
