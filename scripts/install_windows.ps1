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

# 1. Find Python — prefer system Python 3.10+ over a venv interpreter so the
# scheduled task runs as a plain Python process, not a venv-bound one.
$candidates = @($(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'), $(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'), $(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python310\python.exe'))
$python = $null
foreach ($p in $candidates) {
    if ($p -and (Test-Path $p)) { $python = $p; break }
}
if (-not $python) {
    $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
if (-not $python) {
    Write-Error "python.exe not found. Install Python 3.10+ (e.g. python.org installer) and re-run."
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
# Write as UTF-16 LE with BOM — the schtasks.exe CLI on Windows expects
# exactly this encoding for /XML input.
[System.IO.File]::WriteAllText($built, $xml, [System.Text.UnicodeEncoding]::new($false, $true))

# 4. Register the task via schtasks.exe (Register-ScheduledTask -Xml has
# problems with the PowerShell 5.1 string re-encoding on some hosts).
$taskName = 'drop-watch'
$ErrorActionPreference = 'Continue'
schtasks.exe /Query /TN $taskName *> $null
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -eq 0) {
    schtasks.exe /Delete /TN $taskName /F
    Write-Host "Removed existing task '$taskName'."
}
schtasks.exe /Create /TN $taskName /XML $built
Write-Host "Registered task '$taskName'. It will run 30s after each logon."
Write-Host "Start it now with: schtasks.exe /Run /TN drop-watch"
$logFile = Join-Path $ProjectDir 'logs\drop_watch.log'
Write-Host ("Tail logs with   : Get-Content '" + $logFile + "' -Wait")
