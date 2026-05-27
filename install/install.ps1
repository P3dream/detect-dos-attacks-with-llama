$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$BASE_DIR = Resolve-Path "$SCRIPT_DIR\.."

Write-Host "=============================="
Write-Host "Genguardian Setup"
Write-Host "=============================="

# -------------------------
# STEP 1 - PYTHON
# -------------------------
Write-Progress -Activity "Genguardian Setup" -Status "Verificando Python..." -PercentComplete 10

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python não encontrado"
    exit 1
}

# -------------------------
# STEP 2 - OLLAMA
# -------------------------
Write-Progress -Activity "Genguardian Setup" -Status "Verificando Ollama..." -PercentComplete 25

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "[INFO] Instalando Ollama..."
    Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile "$SCRIPT_DIR\ollama.exe"
    Start-Process "$SCRIPT_DIR\ollama.exe" -ArgumentList "/S" -Wait
}

# -------------------------
# STEP 3 - VENV
# -------------------------
Write-Progress -Activity "Genguardian Setup" -Status "Criando ambiente virtual..." -PercentComplete 40

if (-not (Test-Path "$BASE_DIR\venv")) {
    python -m venv "$BASE_DIR\venv"
}

$pythonVenv = "$BASE_DIR\venv\Scripts\python.exe"

# -------------------------
# STEP 4 - DEPENDÊNCIAS
# -------------------------
Write-Progress -Activity "Genguardian Setup" -Status "Instalando dependências..." -PercentComplete 60

& $pythonVenv -m pip install --upgrade pip
& $pythonVenv -m pip install -r "$BASE_DIR\requirements.txt"

# -------------------------
# STEP 5 - MODELO
# -------------------------
Write-Progress -Activity "Genguardian Setup" -Status "Baixando modelo (~800MB)..." -PercentComplete 80

$bootstrap = "$SCRIPT_DIR\bootstrap.py"

if (-not (Test-Path $bootstrap)) {
    Write-Host "[ERROR] bootstrap.py não encontrado"
    exit 1
}

& $pythonVenv $bootstrap

# -------------------------
# FINAL
# -------------------------
Write-Progress -Activity "Genguardian Setup" -Status "Finalizando..." -PercentComplete 100

Write-Host "=============================="
Write-Host "SETUP CONCLUÍDO"
Write-Host "=============================="

pause