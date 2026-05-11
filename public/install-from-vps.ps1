$ErrorActionPreference = "Stop"

$ZipUrl = if ($env:CODEXAUTH_ZIP_URL) {
  $env:CODEXAUTH_ZIP_URL
} else {
  "https://github.com/thsangyk-oss/codexauth/archive/refs/heads/main.zip"
}

$InstallRoot = if ($env:CODEXAUTH_INSTALL_DIR) {
  [System.IO.Path]::GetFullPath($env:CODEXAUTH_INSTALL_DIR)
} else {
  Join-Path $env:LOCALAPPDATA "codexauth"
}

$AppDir = Join-Path $InstallRoot "app"
$TempDir = Join-Path $env:TEMP ("codexauth-" + [guid]::NewGuid().ToString("N"))
$ZipPath = Join-Path $TempDir "codexauth-main.zip"
$ExtractDir = Join-Path $TempDir "extract"

New-Item -ItemType Directory -Force -Path $TempDir, $ExtractDir, $AppDir | Out-Null

# Stop any running codexauth node process (so files in $AppDir aren't locked during update)
Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object {
  try {
    $_.Path -and $_.Path.StartsWith($InstallRoot, [System.StringComparison]::OrdinalIgnoreCase)
  } catch { $false }
} | ForEach-Object {
  Write-Host "Stopping running codexauth (PID $($_.Id))..."
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 600

Write-Host "Downloading codexauth from GitHub: $ZipUrl"
Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing

Write-Host "Extracting to $AppDir"
Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
$SourceDir = Join-Path $ExtractDir "codexauth-main"
Copy-Item -Path (Join-Path $SourceDir "*") -Destination $AppDir -Recurse -Force

Remove-Item -Path $TempDir -Recurse -Force

Write-Host "Running Windows setup from $AppDir"
Set-Location $AppDir
powershell -NoProfile -ExecutionPolicy Bypass -File ".\install-windows.ps1"
