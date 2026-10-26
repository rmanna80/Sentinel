#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
foreach ($name in @('Sentinel Server', 'Sentinel Agent')) {
    if (Get-ScheduledTask -TaskPath '\Sentinel\' -TaskName $name -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskPath '\Sentinel\' -TaskName $name -Confirm:$false
        Write-Host "Removed \Sentinel\$name"
    }
}
