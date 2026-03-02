#!/usr/bin/env python3
"""
analyze_log.py
==============
Lê o requests.log e calcula médias de CPU, GPU, memória e tempo de resposta.
"""

import json
import sys
import os

LOG_PATH = "requests.log"

def load_log(path):
    """Lê o arquivo .log que é uma sequência de JSONs separados por vírgula"""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    # Remove vírgula final se houver e envolve em array
    if content.endswith(","):
        content = content[:-1]
    content = f"[{content}]"

    return json.loads(content)

def analyze(records):
    times       = []
    cpu_peaks   = []
    cpu_avgs    = []
    gpu_utils   = []
    gpu_vrams   = []
    ollama_mems = []
    server_mems = []
    errors      = 0

    for r in records:
        if "error" in r:
            errors += 1
            continue

        try:
            times.append(float(r["timings"]["total"].replace(" s", "")))
        except Exception:
            pass

        try:
            cpu = r["cpu_percent"]
            cpu_peaks.append(float(cpu["peak"]))
            cpu_avgs.append(float(cpu["avg"]))
        except Exception:
            pass

        try:
            gpu = r["gpu"]
            gpu_utils.append(float(gpu["util_percent"]))
            gpu_vrams.append(float(gpu["vram_used_MB"]))
        except Exception:
            pass

        try:
            mem = r["memory"]
            ollama_mems.append(float(mem["ollama_rss_MB"]))
            server_mems.append(float(mem["server_rss_MB"]))
        except Exception:
            pass

    def avg(lst):
        return round(sum(lst) / len(lst), 3) if lst else None

    def mn(lst):
        return round(min(lst), 3) if lst else None

    def mx(lst):
        return round(max(lst), 3) if lst else None

    print(f"\n{'='*50}")
    print(f"  📊 Análise do requests.log")
    print(f"{'='*50}")
    print(f"  Total de requisições: {len(records)}")
    print(f"  Erros:                {errors}")
    print(f"  Requisições válidas:  {len(records) - errors}")

    print(f"\n  ⏱️  Tempo de resposta (s):")
    print(f"     Média:  {avg(times)}")
    print(f"     Mínimo: {mn(times)}")
    print(f"     Máximo: {mx(times)}")

    print(f"\n  🖥️  CPU do Ollama (%):")
    print(f"     Pico médio: {avg(cpu_peaks)}")
    print(f"     Avg médio:  {avg(cpu_avgs)}")
    print(f"     Pico máx:   {mx(cpu_peaks)}")

    if gpu_utils:
        print(f"\n  🎮  GPU (RTX 4050):")
        print(f"     Utilização média: {avg(gpu_utils)}%")
        print(f"     Utilização máx:   {mx(gpu_utils)}%")
        print(f"     VRAM média:       {avg(gpu_vrams)} MB")
        print(f"     VRAM máx:         {mx(gpu_vrams)} MB")
    else:
        print(f"\n  🎮  GPU: dados não disponíveis no log")

    print(f"\n  💾  Memória RAM:")
    print(f"     Ollama média: {avg(ollama_mems)} MB")
    print(f"     Ollama máx:   {mx(ollama_mems)} MB")
    print(f"     Servidor:     {avg(server_mems)} MB")

    print(f"\n{'='*50}\n")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_PATH

    if not os.path.exists(path):
        print(f"❌ Arquivo não encontrado: {path}")
        sys.exit(1)

    print(f"📂 Lendo: {path}")
    records = load_log(path)
    analyze(records)
