$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (!(Test-Path "dist/OpenTaskMonitor/OpenTaskMonitor.exe")) {
    throw "Build the portable app first: ./scripts/build.ps1"
}
$compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($compiler) {
    $iscc = $compiler.Source
} else {
    $iscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6/ISCC.exe"
}
if (!(Test-Path $iscc)) {
    throw "Inno Setup 6 is required. Install from https://jrsoftware.org/isinfo.php or use GitHub Actions."
}
$version = python -c "from opentask import __version__; print(__version__)"
if ($LASTEXITCODE -ne 0) { throw "Cannot read application version" }
& $iscc "/DAppVersion=$version" "installer/OpenTaskMonitor.iss"
if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed" }
Write-Host "Installer is in release/"
