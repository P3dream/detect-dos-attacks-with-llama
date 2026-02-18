#!/usr/bin/env python3
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List
from uuid import uuid4
from datetime import datetime
from ollama import chat
import json
import psutil
import os
import re

# ----------------- Instância da API -----------------
app = FastAPI(title="DoS Detection API")

# ----------------- Schemas -----------------
class DosAnalysis(BaseModel):
    dos_attack_probability: int
    justification: str
#    ip_origin: List[str]

# ----------------- Config -----------------
REQUESTS_LOG_PATH = "requests.log"
results_by_id = {}  # memória simples

# ----------------- Helpers -----------------
def append_requests_log(obj):
    try:
        with open(REQUESTS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, indent=2) + ",\n")
    except Exception as e:
        print("❌ Falha ao gravar requests.log:", e)

def measure_resources(start_time):
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    elapsed = (datetime.now() - start_time).total_seconds()
    return {
        "timings": {"total": f"{elapsed:.3f} s"},
        "memory": {
            "rss_MB": round(mem_info.rss / 1024 / 1024, 2),
            "vms_MB": round(mem_info.vms / 1024 / 1024, 2)
        },
        "cpu_percent": process.cpu_percent(interval=None)
    }

# ----------------- Endpoint principal -----------------
@app.post("/ia")
async def analyze_packets(request: Request):
    start_time = datetime.now()
    data = await request.json()  # pega qualquer JSON enviado
    print("📥 Recebido:", data)

    exec_id = str(uuid4())
    try:
        # Construir prompt
        prompt = f"""
Analyze the following network flow and determine the probability (0-100) of a SYN TCP Flooding DoS attack.
Return STRICTLY a single JSON object matching the schema:

{{
    "dos_attack_probability": 0,
    "justification": "string"
}}

<flow>
{data}
</flow>
"""

        # Medir tokens (simples contagem de palavras)
        token_count = len(prompt.split())
        print(f"📥 Prompt length: {len(prompt)} chars")
        print(f"🔢 Token count (approx): {token_count}")

        # ---------- Envio ao modelo Ollama ----------
        response = chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a network security analyst specialized in detecting SYN TCP flooding DDoS attacks. Always respond only with valid JSON matching the schema."
                },
                {"role": "user", "content": prompt}
            ],
            model="llama3.2:1b",
            format=DosAnalysis.model_json_schema(),
            stream=False
        )

        content = (response.message.content or "").strip()
        print("🧠 Raw Ollama response:", content)

        # Parsing seguro
        try:
            result = DosAnalysis.model_validate_json(content)
        except Exception:
            match = re.search(r"\{[\s\S]*\}", content)
            if not match:
                raise ValueError("Não foi possível encontrar JSON válido na resposta do modelo.")
            result = DosAnalysis.model_validate_json(match.group(0))

        results_by_id[exec_id] = result
        print("✅ Parsed result:", result)

        # Métricas
        metrics = measure_resources(start_time)

        # Salvar log
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
    uvicorn.run("server_prob:app", host="0.0.0.0", port=3000, reload=True)
