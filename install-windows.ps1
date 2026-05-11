$ErrorActionPreference = "Stop"

function Test-Command($Name) {
  $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function New-DesktopShortcut($ProjectDir) {
  $Desktop = [Environment]::GetFolderPath("Desktop")
  if (-not $Desktop) { return }

  $StartScript = Join-Path $ProjectDir "start-codexauth.ps1"
  $ShortcutPath = Join-Path $Desktop "codexauth.lnk"
  $Shell = New-Object -ComObject WScript.Shell
  $Shortcut = $Shell.CreateShortcut($ShortcutPath)
  $Shortcut.TargetPath = "powershell.exe"
  $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$StartScript`""
  $Shortcut.WorkingDirectory = $ProjectDir
  $IconPath = Join-Path $ProjectDir "public\favicon.ico"
  if (Test-Path $IconPath) {
    $Shortcut.IconLocation = $IconPath
  } else {
    $Shortcut.IconLocation = Join-Path $env:SystemRoot "System32\shell32.dll,220"
  }
  $Shortcut.Description = "Start codexauth and open the dashboard"
  $Shortcut.Save()
  Write-Host "Desktop shortcut created: $ShortcutPath"
}

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

if (-not (Test-Command "node")) {
  if (Test-Command "winget") {
    winget install OpenJS.NodeJS.LTS --exact --silent --accept-package-agreements --accept-source-agreements
  } else {
    throw "Node.js is not installed and winget was not found. Install Node.js 18+ first: https://nodejs.org/"
  }
}

$Npm = "npm"
$NodeInstallNpm = Join-Path $env:ProgramFiles "nodejs\npm.cmd"
if (-not (Test-Command "npm") -and (Test-Path $NodeInstallNpm)) {
  $Npm = $NodeInstallNpm
}

$DefaultCodexAuth = Join-Path $env:USERPROFILE ".codex\auth.json"

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DefaultCodexAuth) | Out-Null

if (-not (Test-Path $DefaultCodexAuth)) {
  "{}" | Set-Content -Path $DefaultCodexAuth -Encoding UTF8
}

& $Npm install
New-DesktopShortcut $ProjectDir

Write-Host ""
Write-Host "codexauth is ready."
Write-Host "Desktop shortcut: codexauth"
Write-Host "Opening http://localhost:8801"
Write-Host ""

powershell -NoProfile -ExecutionPolicy Bypass -File ".\start-codexauth.ps1"
