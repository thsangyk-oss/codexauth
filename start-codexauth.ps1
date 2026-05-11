$ErrorActionPreference = "Stop"

function Test-Command($Name) {
  $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-Dashboard($BaseUrl) {
  try {
    $res = Invoke-WebRequest -Uri "$BaseUrl/api/health" -UseBasicParsing -TimeoutSec 2
    return $res.StatusCode -ge 200 -and $res.StatusCode -lt 500
  } catch {
    return $false
  }
}

$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Port = if ($env:PORT) { [int]$env:PORT } else { 8801 }
$BaseUrl = "http://localhost:$Port"

$Node = "node"
$NodeExe = Join-Path $env:ProgramFiles "nodejs\node.exe"
if (-not (Test-Command "node") -and (Test-Path $NodeExe)) {
  $Node = $NodeExe
}

if (-not (Test-Command "node") -and -not (Test-Path $Node)) {
  throw "Node.js was not found. Run install-windows.ps1 first."
}

if (-not (Test-Dashboard $BaseUrl)) {
  $LogDir = Join-Path $env:LOCALAPPDATA "codexauth\logs"
  $ServerLog = Join-Path $LogDir "server.log"
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

  $ServerCommand = "cd /d `"$AppDir`" && `"$Node`" server.js >> `"$ServerLog`" 2>&1"
  Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $ServerCommand) -WindowStyle Minimized

  for ($i = 0; $i -lt 30; $i++) {
    if (Test-Dashboard $BaseUrl) { break }
    Start-Sleep -Seconds 1
  }
}

Start-Process $BaseUrl
