$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
# Use the active Python / venv. Build only on Windows x64, never cross-compile.
python -c "import sys,struct; assert sys.platform == 'win32' and struct.calcsize('P') == 8, 'Windows x64 required'"
if ($LASTEXITCODE -ne 0) { throw "Windows x64 Python is required" }
python -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }
python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
python -m PyInstaller --noconfirm --clean --onedir --windowed --name OpenTaskMonitor --noupx --collect-data psutil scripts/launcher.py
if ($LASTEXITCODE -ne 0) { throw "Build failed" }
Copy-Item LICENSE,README.md,THIRD_PARTY_NOTICES.md,SECURITY.md,VERIFICATION.md -Destination dist/OpenTaskMonitor/
Copy-Item docs -Destination dist/OpenTaskMonitor/docs -Recurse -Force
Copy-Item docs/USER_GUIDE.md -Destination dist/OpenTaskMonitor/START-HERE.md
python scripts/collect_licenses.py dist/OpenTaskMonitor
if ($LASTEXITCODE -ne 0) { throw "License collection failed" }
Compress-Archive -Path dist/OpenTaskMonitor -DestinationPath OpenTaskMonitor-windows-x64.zip -Force
Write-Host "Ready: OpenTaskMonitor-windows-x64.zip"
Write-Host "Extract the entire archive before running OpenTaskMonitor/OpenTaskMonitor.exe"
