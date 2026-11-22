$ErrorActionPreference = "Stop"

Write-Host "GuardSnitch.ai installer" -ForegroundColor Cyan

$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $python) {
    throw "Python 3.9+ is required. Install Python from https://www.python.org/downloads/ then reopen PowerShell."
}

$version = & $python.Source --version 2>&1
if ($version -notmatch "Python (\d+)\.(\d+)") {
    throw "Could not determine the Python version."
}
$major = [int]$Matches[1]
$minor = [int]$Matches[2]
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 9)) {
    throw "Python 3.9 or newer is required."
}

$venv = Join-Path $PSScriptRoot ".venv"
if (-not (Test-Path $venv)) {
    & $python.Source -m venv $venv
}

$pip = Join-Path $venv "Scripts\python.exe"
& $pip -m pip install --upgrade pip setuptools wheel
& $pip -m pip install -e $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "GuardSnitch.ai installation failed."
}

& $pip -m guardsnitch.cli shield startup install
if ($LASTEXITCODE -ne 0) {
    throw "The reverse-shell shield could not be registered for Windows sign-in."
}

Write-Host ""
Write-Host "Installed GuardSnitch.ai and enabled the background shield." -ForegroundColor Green
Write-Host 'Open a new PowerShell and run: GuardSnitch.ai -h'
