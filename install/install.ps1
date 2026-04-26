$ErrorActionPreference = "Stop"

# Garante UTF-8 no console (evita lixo de encoding)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "=============================="
Write-Host "Genguardian Installer START"
Write-Host "=============================="

Write-Host "[INFO] Path: $(Get-Location)"

# -------------------------
# GIT CHECK
# -------------------------
if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Git encontrado"
} else {
    Write-Host "[ERROR] Git não encontrado"
    exit 1
}

# -------------------------
# PYTHON CHECK
# -------------------------
if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Python encontrado"
} else {
    Write-Host "[ERROR] Python não encontrado"
    exit 1
}

# -------------------------
# OLLAMA CHECK / INSTALL
# -------------------------
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Ollama já instalado"
} else {
    Write-Host "[INFO] Instalando Ollama..."
    Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile "ollama.exe"
    Start-Process ".\ollama.exe" -ArgumentList "/S" -Wait
    Write-Host "[OK] Ollama instalado"
}

# -------------------------
# REPO SETUP
# -------------------------
$repo = "https://github.com/SEU_USER/SEU_REPO.git"
$folder = "genguardian"

if (-not (Test-Path $folder)) {
    Write-Host "[INFO] Clonando repositório..."
    git clone $repo
} else {
    Write-Host "[OK] Repositório já existe"
}

Set-Location $folder

Write-Host "[INFO] Diretório atual: $(Get-Location)"

# -------------------------
# VENV
# -------------------------
if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Criando venv..."
    python -m venv venv
} else {
    Write-Host "[OK] venv já existe"
}

# Ativação (mais confiável no Windows)
$venvActivate = ".\venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    Write-Host "[INFO] Ativando venv..."
    & $venvActivate
} else {
    Write-Host "[ERROR] venv não encontrado"
    exit 1
}

# -------------------------
# DEPENDÊNCIAS
# -------------------------
Write-Host "[INFO] Instalando dependências..."
python -m pip install --upgrade pip
pip install -r requirements.txt

# -------------------------
# BOOTSTRAP
# -------------------------
Write-Host "[INFO] Executando bootstrap..."
python bootstrap.py

# -------------------------
# FINAL
# -------------------------
Write-Host "=============================="
Write-Host "🔥 INSTALL FINALIZADO COM SUCESSO"
Write-Host "==============================""