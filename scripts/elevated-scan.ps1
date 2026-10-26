#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the elevated scan jobs you queued in the dashboard, then exits.
.DESCRIPTION
    Some checks need administrator rights (BitLocker/Device encryption, Secure Boot, the Security event log).
    Queue an "elevated" scan in the dashboard, then run this from a normal PowerShell window. Windows shows its
    permission (UAC) prompt; the protected copy of the agent in Program Files takes the elevated jobs, runs them
    read-only and exits after 30 idle seconds.

    The elevated process never runs code from this repository or its .venv, because a standard user can change
    those. Install the protected copy once with scripts\install-elevated-agent.ps1 (as administrator).
    Sentinel never stores administrator credentials and never elevates itself.
#>
$ErrorActionPreference = 'Stop'

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$launcher = Join-Path $programFiles 'Sentinel\elevated-run.ps1'
if (-not (Test-Path $launcher)) {
    Write-Host 'Elevated scans use a protected copy of the agent that is not installed yet.' -ForegroundColor Yellow
    Write-Host 'Install it once from an administrator PowerShell window:'
    Write-Host "    powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\install-elevated-agent.ps1`""
    exit 1
}

# Windows PowerShell from System32 (known folder, not PATH); -NoProfile so no user-writable profile script runs.
$powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
Write-Host 'Windows will ask for permission to run the elevated scan...' -ForegroundColor Cyan
$psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$launcher`"")
$proc = Start-Process -FilePath $powershell -ArgumentList $psArgs -Verb RunAs -Wait -PassThru
exit $proc.ExitCode
