import json
import subprocess
from pathlib import Path
from huggingface_hub import hf_hub_download
from utils_hash import sha256_file

print("[BOOTSTRAP] iniciado")

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent

MANIFEST_PATH = SCRIPT_DIR / "model_manifest.json"
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

if not MANIFEST_PATH.exists():
    raise Exception(f"[ERROR] manifest não encontrado: {MANIFEST_PATH}")

with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
    manifest = json.load(f)

gguf_path = MODEL_DIR / manifest["gguf"]
modelfile_path = MODEL_DIR / manifest["modelfile"]

print("[INFO] baixando/verificando modelo...")

if not gguf_path.exists():
    print("[INFO] baixando GGUF...")
    hf_hub_download(
        repo_id=manifest["repo"],
        filename=manifest["gguf"],
        local_dir=str(MODEL_DIR),
        local_dir_use_symlinks=False
    )

if not modelfile_path.exists():
    print("[INFO] baixando Modelfile...")
    hf_hub_download(
        repo_id=manifest["repo"],
        filename=manifest["modelfile"],
        local_dir=str(MODEL_DIR),
        local_dir_use_symlinks=False
    )

print("[INFO] validando hash...")

expected = manifest.get("sha256")
if expected and expected != "PUT_YOUR_HASH_HERE":
    if sha256_file(gguf_path) != expected:
        raise Exception("[ERROR] modelo corrompido")

print("[OK] modelo validado")

MODEL_NAME = "genguardian-multiclass"

print("[INFO] verificando modelo no ollama...")

result = subprocess.run(
    ["ollama", "list"],
    capture_output=True,
    text=True
)

if MODEL_NAME not in result.stdout:
    print("[INFO] criando modelo no ollama... (pode levar alguns minutos)")

    proc = subprocess.run(
        ["ollama", "create", MODEL_NAME, "-f", str(modelfile_path.resolve())]
    )

    if proc.returncode != 0:
        raise Exception("[ERROR] falha ao criar modelo no ollama")

    print("[OK] modelo criado")
else:
    print("[OK] modelo já existe")

print("[BOOTSTRAP] finalizado")