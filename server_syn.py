#!/usr/bin/env python3
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime
from ollama import chat
from contextlib import asynccontextmanager
import json
import psutil
import os
import re
import threading
import pynvml

# ----------------- Config -----------------
REQUESTS_LOG_PATH = "syn.requests.log"
results_by_id = {}
_ollama_proc = None
_gpu_handle = None
CPU_COUNT = psutil.cpu_count()

# ----------------- Lifespan -----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _ollama_proc, _gpu_handle
    best_pid = None
    best_mem = 0

    for proc in psutil.process_iter(['name', 'pid', 'memory_info']):
        try:
            if proc.info['name'].lower() == 'ollama.exe':
                mem = proc.info['memory_info'].rss / 1024 / 1024
                print(f"✅ PID: {proc.info['pid']} | Memória: {mem:.0f} MB")
                if mem > best_mem:
                    best_mem = mem
                    best_pid = proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if best_pid:
        _ollama_proc = psutil.Process(best_pid)
        print(f"🎯 Usando PID {best_pid} — {best_mem:.0f} MB")
    else:
        print("⚠️ Processo ollama.exe não encontrado")

    try:
        pynvml.nvmlInit()
        _gpu_handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        gpu_name = pynvml.nvmlDeviceGetName(_gpu_handle)
        print(f"✅ GPU encontrada: {gpu_name}")
    except Exception as e:
        print(f"⚠️ GPU não disponível: {e}")

    yield

    try:
        pynvml.nvmlShutdown()
    except Exception:
        pass

# ----------------- Instância da API -----------------
app = FastAPI(title="DoS Detection API", lifespan=lifespan)

# ----------------- Schemas -----------------
class DosAnalysis(BaseModel):
    classification: str
    justification: str

# ----------------- Helpers -----------------
def append_requests_log(obj):
    try:
        with open(REQUESTS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, indent=2) + ",\n")
    except Exception as e:
        print("❌ Falha ao gravar requests.log:", e)

def sample_ollama_cpu(stop_event, samples):
    while not stop_event.is_set():
        if _ollama_proc:
            try:
                samples.append(_ollama_proc.cpu_percent(interval=0.2))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

def measure_resources(start_time, peak_cpu=0.0, avg_cpu=0.0):
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    elapsed = (datetime.now() - start_time).total_seconds()

    ollama_rss = 0.0
    if _ollama_proc:
        try:
            ollama_rss = _ollama_proc.memory_info().rss / 1024 / 1024
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    gpu_util     = 0
    gpu_mem_used = 0
    try:
        if _gpu_handle:
            gpu_info     = pynvml.nvmlDeviceGetUtilizationRates(_gpu_handle)
            gpu_mem      = pynvml.nvmlDeviceGetMemoryInfo(_gpu_handle)
            gpu_util     = gpu_info.gpu
            gpu_mem_used = round(gpu_mem.used / 1024 / 1024, 2)
    except Exception:
        pass

    return {
        "timings": {"total": f"{elapsed:.3f} s"},
        "memory": {
            "server_rss_MB": round(mem_info.rss / 1024 / 1024, 2),
            "ollama_rss_MB": round(ollama_rss, 2),
        },
        "cpu_percent": {
            "peak": round(peak_cpu / CPU_COUNT, 2),
            "avg":  round(avg_cpu  / CPU_COUNT, 2)
        },
        "gpu": {
            "util_percent": gpu_util,
            "vram_used_MB": gpu_mem_used
        }
    }

def format_flow_for_prompt(data: dict) -> str:
    return (
        f"Flow Duration={data.get('Flow Duration', 0)}, "
        f"Flow Packets/s={data.get('Flow Packets/s', 0)}, "
        f"Avg Fwd Segment Size={data.get('Avg Fwd Segment Size', 0)}, "
        f"Average Packet Size={data.get('Average Packet Size', 0)}, "
        f"Init_Win_bytes_forward={data.get('Init_Win_bytes_forward', 0)}"
    )

# ----------------- Endpoint principal -----------------
@app.post("/ia")
async def analyze_packets(request: Request):
    start_time = datetime.now()
    data = await request.json()
    print("📥 Recebido:", data)

    exec_id = str(uuid4())

    # aceita lista (prompt direto do script de teste) ou dict (flow estruturado)
    if isinstance(data, list):
        flow_text = data[0]
    elif isinstance(data, dict) and data.get("raw"):
        flow_data = {k: v for k, v in data.items() if k != "raw"}
        flow_text = format_flow_for_prompt(flow_data)
    else:
        flow_text = format_flow_for_prompt(data)

    try:
        prompt = f"""
            Analyze the following network flow and classify it strictly as either BENIGN or SYN.

            Return STRICTLY a single JSON object matching the schema:

            {{
                "classification": "BENIGN" or "SYN",
                "justification": "It was classified like this because of... "
            }}

            <flow>
            {flow_text}
            </flow>
            """
        token_count = len(prompt.split())
        print(f"📥 Prompt length: {len(prompt)} chars")
        print(f"🔢 Token count (approx): {token_count}")

        cpu_samples = []
        stop_event  = threading.Event()
        cpu_thread  = threading.Thread(target=sample_ollama_cpu, args=(stop_event, cpu_samples), daemon=True)
        cpu_thread.start()

        response = chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a network security analyst specialized in detecting SYN TCP flooding DDoS attacks. Respond only with valid JSON containing the field 'classification' (BENIGN or SYN) and 'justification'."
                },
                {"role": "user", "content": prompt}
            ],
            model="llama-syn-finetuned-classify:latest",
            format=DosAnalysis.model_json_schema(),
            stream=False
        )

        stop_event.set()
        cpu_thread.join(timeout=1)

        peak_cpu = max(cpu_samples) if cpu_samples else 0.0
        avg_cpu  = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0

        content = (response.message.content or "").strip()
        print("🧠 Raw Ollama response:", content)

        try:
            result = DosAnalysis.model_validate_json(content)
        except Exception:
            match = re.search(r"\{[\s\S]*\}", content)
            if not match:
                raise ValueError("Não foi possível encontrar JSON válido na resposta do modelo.")
            result = DosAnalysis.model_validate_json(match.group(0))

        results_by_id[exec_id] = result
        print("✅ Parsed result:", result)

        metrics = measure_resources(start_time, peak_cpu, avg_cpu)

        log_data = {
            "id": exec_id,
            "datetime": start_time.isoformat(),
            "requestTokens": token_count,
            "requestChars": len(prompt),
            "request": data,
            "response": result.dict(),
            **metrics
        }
        append_requests_log(log_data)

        return {"exec_id": exec_id, "result": result}

    except Exception as e:
        append_requests_log({
            "id": exec_id,
            "datetime": datetime.now().isoformat(),
            "error": str(e),
            "request": data
        })
        print("❌ Erro ao processar a requisição:", e)
        raise HTTPException(status_code=500, detail="Erro interno ao processar a solicitação.")

# ----------------- Endpoint auxiliar -----------------
@app.get("/analise/{exec_id}")
async def get_result(exec_id: str):
    result = results_by_id.get(exec_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return result

# ----------------- Test endpoint -----------------
@app.get("/test")
async def test():
    return {"status": "API is running. Use POST /ia with packet data to analyze."}

# ----------------- Inicialização -----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server_syn:app", host="0.0.0.0", port=3000, reload=True)