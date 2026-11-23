$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$ollamaCommand = Get-Command ollama -ErrorAction SilentlyContinue
$ollamaBinary = if ($ollamaCommand) { $ollamaCommand.Source } else { Join-Path $PSScriptRoot 'data/ollama/ollama.exe' }
if (-not (Test-Path -LiteralPath $ollamaBinary)) { throw 'Ollama not found. Install Ollama for Windows first.' }
$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
if (-not $ollamaCommand) { $env:OLLAMA_MODELS = Join-Path $PSScriptRoot 'data/models' }
try { $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/version' -TimeoutSec 2 }
catch {
    New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot 'data') | Out-Null
    Start-Process -FilePath $ollamaBinary -ArgumentList 'serve' -WindowStyle Hidden -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $PSScriptRoot 'data/ollama-out.log') -RedirectStandardError (Join-Path $PSScriptRoot 'data/ollama-error.log') | Out-Null
}
python server.py
