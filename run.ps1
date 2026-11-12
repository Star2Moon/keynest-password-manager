$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    $keynestPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $keynestPython) {
        & $keynestPython app.py
    } else {
        python app.py
    }
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
