$ErrorActionPreference = "Stop"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "=============================="
Write-Host "Genguardian Installer START"
Write-Host "=============================="

Write-Host "[INFO] Path: $(Get-Location)"

# -------------------------
# CHECKS
# -------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Git não encontrado"
    exit 1
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python não encontrado"
    exit 1
}

Write-Host "[OK] Git e Python OK"

# -------------------------
# OLLAMA
# -------------------------
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "[INFO] Instalando Ollama..."
    Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile "ollama.exe"
    Start-Process ".\ollama.exe" -ArgumentList "/S" -Wait
}

Write-Host "[OK] Ollama OK"

# -------------------------
# REPO
# -------------------------
$repo = "https://github.com/P3dream/detect-dos-attacks-with-llama"
$folder = "detect-dos-attacks-with-llama"

if (-not (Test-Path $folder)) {
    Write-Host "[INFO] Clonando repositório..."
    git clone $repo
}

Set-Location $folder

$BASE_DIR = Get-Location
Write-Host "[INFO] Dentro de: $BASE_DIR"

# -------------------------
# VENV
# -------------------------
if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Criando venv..."
    python -m venv venv
}

$pythonVenv = "$BASE_DIR\venv\Scripts\python.exe"

# -------------------------
# DEPENDÊNCIAS
# -------------------------
Write-Host "[INFO] Instalando dependências..."
& $pythonVenv -m pip install --upgrade pip
& $pythonVenv -m pip install -r "$BASE_DIR\requirements.txt"

# -------------------------
# BOOTSTRAP (FIX DEFINITIVO)
# -------------------------
$bootstrap = "$BASE_DIR\bootstrap.py"

if (-not (Test-Path $bootstrap)) {
    Write-Host "[ERROR] bootstrap.py não encontrado em $bootstrap"
    exit 1
}

Write-Host "[INFO] Executando bootstrap..."
& $pythonVenv $bootstrap

# -------------------------
# FINAL
# -------------------------
Write-Host "=============================="
Write-Host "INSTALL FINALIZADO COM SUCESSO"
Write-Host "=============================="