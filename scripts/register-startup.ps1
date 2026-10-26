#Requires -Version 5.1
<#
.SYNOPSIS
    Starts the Sentinel server and agent automatically when you sign in.
.DESCRIPTION
    Creates two Task Scheduler tasks that run as YOU (not as administrator or SYSTEM), only while you
    are signed in, with hidden windows. Remove them with scripts\unregister-startup.ps1.
    If Windows reports "Access is denied", run this once from an administrator PowerShell; the tasks
    still run with your normal rights.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$uv = (Get-Command uv -ErrorAction Stop).Source
$user = "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

$tasks = @(
    @{ Name = 'Sentinel Server'; Args = 'run sentinel-server serve'; Delay = 'PT10S' },
    @{ Name = 'Sentinel Agent';  Args = 'run sentinel-agent run';    Delay = 'PT40S' }
)
foreach ($t in $tasks) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $trigger.Delay = $t.Delay
    $action = New-ScheduledTaskAction -Execute $uv -Argument $t.Args -WorkingDirectory $repo
    Register-ScheduledTask -TaskName $t.Name -TaskPath '\Sentinel\' -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Sentinel local security monitor' -Force | Out-Null
    Write-Host "Registered task \Sentinel\$($t.Name) (runs as $user, not elevated)." -ForegroundColor Green
}
Write-Host "They start at your next sign-in. Start them now with: Start-ScheduledTask -TaskPath '\Sentinel\' -TaskName 'Sentinel Server'"
