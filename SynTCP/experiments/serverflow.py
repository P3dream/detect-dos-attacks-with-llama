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

app = FastAPI(title="DoS Detection API for Flows")

# ----------------- Schemas -----------------
class DosAnalysis(BaseModel):
    dos_attack_probability: int
    justification: str
    ip_origin: List[str]

# ----------------- Config -----------------
REQUESTS_LOG_PATH = "requests_flows.log"
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
async def analyze_flows(request: Request):
    start_time = datetime.now()
    data = await request.json()  # recebe os fluxos
    print("📥 Recebido:", data)

    exec_id = str(uuid4())
    try:
        # Monta prompt com instruções explícitas para JSON único e campos únicos
        prompt = f"""
        You are a network security analyst specialized in detecting DoS attacks. 
        Analyze the following network flows and determine the probability (0-100) of a DoS attack. 

        Rules:
        1. Ignore flows that are sent to multicast addresses (224.0.0.0/4) unless packet rates are extremely high and unusual for the network.
        2. Consider both forward and backward packet counts, flow duration, bytes per second, and inter-arrival times (IAT) for detecting anomalies.
        3. Return a single JSON object with this schema, strictly:

        {{
            "dos_attack_probability": 0,
            "justification": "string",
            "ip_origin": ["x.x.x.x"]
        }}

        <flows>
        {json.dumps(data)}
        </flows>
"""


        token_count = len(prompt.split())
        print(f"📥 Prompt length: {len(prompt)} chars, approx {token_count} tokens")

        # ---------- Envio ao modelo Ollama ----------
        response = chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a network security analyst. Respond ONLY in valid JSON matching the schema."
                },
                {"role": "user", "content": prompt}
            ],
            model="llama3.1",
            format=DosAnalysis.model_json_schema(),
            stream=False
        )

        content = (response.message.content or "").strip()
        print("🧠 Raw Ollama response:", content)

        # ----------------- Post-processamento -----------------
        # Remove chaves duplicadas mantendo a primeira ocorrência
        try:
            result = DosAnalysis.model_validate_json(content)
        except Exception:
            # extrai primeiro JSON do texto
            match = re.search(r"\{[\s\S]*\}", content)
            if not match:
                raise ValueError("Não foi possível encontrar JSON válido na resposta do modelo.")
            json_text = match.group(0)

            # remove duplicatas (keep first)
            seen_keys = set()
            cleaned = []
            for line in json_text.splitlines():
                key_match = re.match(r'\s*"(.+?)"\s*:', line)
                if key_match:
                    key = key_match.group(1)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                cleaned.append(line)
            json_cleaned = "\n".join(cleaned)
            result = DosAnalysis.model_validate_json(json_cleaned)

        results_by_id[exec_id] = result
        print("✅ Parsed result:", result)

        metrics = measure_resources(start_time)
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
    return {"status": "API is running. Use POST /ia with flow data to analyze."}

# ----------------- Inicialização -----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("serverflow:app", host="0.0.0.0", port=3000, reload=True)
