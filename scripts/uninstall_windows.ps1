<#
.SYNOPSIS
    Remove the drop-watch Task Scheduler entry.
#>
$ErrorActionPreference = 'Stop'
$taskName = 'drop-watch'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Removed task '$taskName'."
} else {
    Write-Host "No task named '$taskName' was registered."
}
