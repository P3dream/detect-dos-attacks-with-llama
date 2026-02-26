#!/usr/bin/env python3
"""
normal_traffic_sim.py
Simula APENAS tráfego legítimo contra TARGET_IP e registra a resposta do detector (/ultima_analise).
Produz um arquivo JSONL: resultados_normal_only.jsonl

Instalação recomendada:
    pip3 install requests
"""

import os
import sys
import time
import json
import random
import subprocess
from datetime import datetime

import requests

# --------------- CONFIG ---------------
WORKDIR = "/home/pedro"
TARGET_IP = "192.168.56.3"  # ajuste para o IP do seu servidor alvo
DETECTOR_URL = "http://192.168.56.1:3000/ultima_analise"  # endpoint que retorna último resultado
OUTPUT_JSONL = os.path.join(WORKDIR, "resultados_normal_only.jsonl")

REPETICOES = 2          # quantas vezes repetir todo o conjunto
POST_WAIT = 2.0         # segundos após o fim do cenário para consultar o detector
COMMAND_TIMEOUT = 180   # timeout máximo (s) para cada comando (safety)

# --------------- CENÁRIOS (somente "normal") ---------------
CENARIOS_NORMAL = [
    # ab leve
    {
        "nome": "normal_ab_leve",
        "cmd": f"ab -n 20 -c 2 http://{TARGET_IP}/",
        "duracao_aproximada": 6,
        "label": "normal"
    },
    # ab médio
    {
        "nome": "normal_ab_medio",
        "cmd": f"ab -n 100 -c 5 http://{TARGET_IP}/",
        "duracao_aproximada": 12,
        "label": "normal"
    },
    # ab pesado
    {
        "nome": "normal_ab_pesado",
        "cmd": f"ab -n 200 -c 20 http://{TARGET_IP}/",
        "duracao_aproximada": 20,
        "label": "normal"
    },
    # curl serial com delays
    {
        "nome": "normal_curl_serial",
        "cmd": f"bash -c 'for i in {{1..30}}; do curl -s http://{TARGET_IP}/ > /dev/null; sleep 0.2; done'",
        "duracao_aproximada": 8,
        "label": "normal"
    },
    # curl concorrente
    {
        "nome": "normal_curl_concorrente",
        "cmd": f"bash -c 'for i in {{1..20}}; do curl -s http://{TARGET_IP}/ > /dev/null & done; wait'",
        "duracao_aproximada": 6,
        "label": "normal"
    },
    # posts simulados
    {
        "nome": "normal_post_simulado",
        "cmd": f"bash -c 'for i in {{1..40}}; do curl -s -X POST -d \"key=value$i\" http://{TARGET_IP}/api > /dev/null; sleep 0.15; done'",
        "duracao_aproximada": 10,
        "label": "normal"
    },
    # picos e ociosidade (pequeno script)
    {
        "nome": "normal_picos_osciosidade",
        "cmd": f"bash -c 'curl -s http://{TARGET_IP}/ > /dev/null; sleep 2; for i in {{1..5}}; do curl -s http://{TARGET_IP}/ > /dev/null; sleep 0.1; done; sleep 1; curl -s http://{TARGET_IP}/ > /dev/null'",
        "duracao_aproximada": 8,
        "label": "normal"
    }
]

# ---------------- helpers ----------------
def append_jsonl(record, path=OUTPUT_JSONL):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def run_command_blocking(cmd, timeout=COMMAND_TIMEOUT, cwd=None):
    """
    Executa um comando shell e aguarda conclusão (captura stdout/stderr).
    Retorna (returncode, stdout, stderr).
    """
    try:
        proc = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        # tenta matar e retorna código especial
        return -9, "", f"timeout:{timeout}"
    except Exception as e:
        return -1, "", str(e)

def fetch_detector(timeout=10):
    try:
        r = requests.get(DETECTOR_URL, timeout=timeout)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"error": "invalid_json", "text": r.text}
        else:
            return {"error": f"status_{r.status_code}", "text": r.text}
    except Exception as e:
        return {"error": f"request_exception:{str(e)}"}

# ---------------- main loop ----------------
def main():
    print("=== Iniciando simulação de tráfego legítimo (apenas NORMAL) ===")
    seq = []
    for _ in range(REPETICOES):
        tmp = CENARIOS_NORMAL.copy()
        random.shuffle(tmp)
        seq.extend(tmp)

    try:
        for c in seq:
            nome = c["nome"]
            cmd = c["cmd"]
            label = c.get("label", "normal")
            approx = c.get("duracao_aproximada", None)

            ts_start = datetime.utcnow().isoformat() + "Z"
            print(f"[{ts_start}] Rodando cenário: {nome} -> {cmd}")

            # Executa o comando
            rc, out, err = run_command_blocking(cmd, timeout=COMMAND_TIMEOUT, cwd=WORKDIR)

            ts_end_command = datetime.utcnow().isoformat() + "Z"
            # aguarda um pouco para detectar (detector pode demorar)
            time.sleep(POST_WAIT)

            # pega resposta do detector (ultima_analise)
            det = fetch_detector(timeout=15)

            registro = {
                "timestamp_start": ts_start,
                "timestamp_end_command": ts_end_command,
                "cenario": nome,
                "label_real": label,
                "cmd": cmd,
                "cmd_returncode": rc,
                "cmd_stdout_snippet": (out or "")[:1000],
                "cmd_stderr_snippet": (err or "")[:1000],
                "detector_result": det
            }

            append_jsonl(registro)
            print(f"[{datetime.utcnow().isoformat() + 'Z'}] Cenário {nome} concluído. detector_result summary: {('error' in det) and det.get('error') or det.get('dos_attack_probability', 'no_prob')}")

            # pausa pequena entre cenários para reduzir sobreposição
            time.sleep(3 + random.uniform(0,2))

    except KeyboardInterrupt:
        print("Interrompido pelo usuário (Ctrl-C). Saindo.")
    finally:
        print("=== Simulação finalizada ===")
        print(f"Resultados gravados em: {OUTPUT_JSONL}")

if __name__ == "__main__":
    main()
