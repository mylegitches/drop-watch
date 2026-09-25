<#
.SYNOPSIS
    Install drop-watch as a Windows Task Scheduler job that runs hidden at logon.

.DESCRIPTION
    - Locates the active Python (python.exe on PATH).
    - Builds a config.local.json by copying config.example.json if not present.
    - Substitutes PYTHON_EXE / PROJECT_DIR / CONFIG_PATH placeholders in drop-watch.xml.
    - Registers the task under \drop-watch (run level: standard user, restart on crash).

.EXAMPLE
    pwsh -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
#>
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Resolve-Path (Join-Path $ScriptDir '..')

# 1. Find Python
$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $python) {
    Write-Error "python.exe not found on PATH. Install Python 3.10+ and ensure it's on PATH."
    exit 1
}
Write-Host "Using Python: $python"

# 2. Ensure config.local.json
$configLocal = Join-Path $ProjectDir 'config.local.json'
if (-not (Test-Path $configLocal)) {
    Copy-Item (Join-Path $ProjectDir 'config.example.json') $configLocal
    Write-Host "Created config.local.json — edit it to set your real targets, then re-run."
}

# 3. Substitute placeholders in XML
$xmlPath = Join-Path $ProjectDir 'scripts\drop-watch.xml'
$xml = Get-Content $xmlPath -Raw
$xml = $xml.Replace('PYTHON_EXE', $python)
$xml = $xml.Replace('PROJECT_DIR', $ProjectDir)
$xml = $xml.Replace('CONFIG_PATH', (Join-Path $ProjectDir 'config.local.json'))
$built = Join-Path $ProjectDir 'scripts\drop-watch.built.xml'
Set-Content -Path $built -Value $xml -Encoding Unicode

# 4. Register the task
$taskName = 'drop-watch'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Removed existing task '$taskName'."
}
Register-ScheduledTask -TaskName $taskName -Xml (Get-Content $built -Raw) | Out-Null
Write-Host "Registered task '$taskName'. It will run 30s after each logon."
Write-Host "Start it now with: Start-ScheduledTask -TaskName drop-watch"
Write-Host "Tail logs with   : Get-Content '$ProjectDir\logs\drop_watch.log' -Wait"
