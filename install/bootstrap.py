import json
import subprocess
from pathlib import Path
from huggingface_hub import hf_hub_download
from utils_hash import sha256_file

MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

manifest = json.load(open("model_manifest.json"))

print("🧠 SBSEG Bootstrap iniciado...")

gguf_path = MODEL_DIR / manifest["gguf"]
modelfile_path = MODEL_DIR / manifest["modelfile"]

# -------------------------
# 1. DOWNLOAD CONTROLADO
# -------------------------
if not gguf_path.exists():
    print("📥 Baixando GGUF...")
    hf_hub_download(
        repo_id=manifest["repo"],
        filename=manifest["gguf"],
        local_dir="models",
        local_dir_use_symlinks=False,
        resume_download=True
    )

if not modelfile_path.exists():
    print("📥 Baixando Modelfile...")
    hf_hub_download(
        repo_id=manifest["repo"],
        filename=manifest["modelfile"],
        local_dir="models",
        local_dir_use_symlinks=False
    )

# -------------------------
# 2. HASH VALIDATION (CRÍTICO SBSEG)
# -------------------------
print("🔐 Validando integridade do modelo...")

file_hash = sha256_file(gguf_path)

if manifest["sha256"] != "PUT_YOUR_HASH_HERE":
    if file_hash != manifest["sha256"]:
        raise Exception("❌ Modelo corrompido ou diferente do esperado!")

print("✅ Modelo validado")

# -------------------------
# 3. OLLAMA CREATE (DETERMINÍSTICO)
# -------------------------
MODEL_NAME = "genguardian-multiclass"

print("🧠 Criando modelo no Ollama...")

result = subprocess.run(["ollama", "list"], capture_output=True, text=True)

if MODEL_NAME not in result.stdout:
    subprocess.run([
        "ollama", "create", MODEL_NAME,
        "-f", str(modelfile_path)
    ], check=True)
else:
    print("✅ Modelo já existe")

# -------------------------
# 4. START SERVER
# -------------------------
print("🚀 Iniciando API...")

subprocess.run([
    "uvicorn",
    "server_udp_lag:app",
    "--host", "0.0.0.0",
    "--port", "3000"
])