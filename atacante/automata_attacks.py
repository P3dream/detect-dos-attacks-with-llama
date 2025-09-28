#!/usr/bin/env python3
"""
automata_attacks.py
Orquestra ataques automaticamente, com watchdog (tempo/bytes),
espera robusta pela resposta da IA (comparando snapshot),
e registra resultados em JSONL.

ALERTA: execute SOMENTE em ambiente isolado/laboratorial.
Instale: pip3 install psutil requests
"""

import os
import sys
import time
import json
import random
import shlex
import signal
import subprocess
from datetime import datetime
from typing import Tuple

try:
    import psutil
except Exception:
    print("psutil não encontrado. Instale: pip3 install psutil")
    raise

import requests
import shutil

# ---------------- CONFIG ----------------
WORKDIR = "/home/pedro"
OUTPUT_JSONL = os.path.join(WORKDIR, "resultados_teste.jsonl")
DETECTOR_URL = "http://192.168.56.1:3000/ultima_analise"
DETECTOR_BY_ID = "http://192.168.56.1:3000/analise"  # usar /analise/{id} se preferir
TARGET_IP = "192.168.56.2"
NET_IFACE = "enp0s3"

GOLDENEYE_PATH = "/home/pedro/GoldenEye/goldeneye.py"
TORSHAMMER_PATH = "/home/pedro/torshammer/torshammer.py"

REPETICOES = 2

# Watchdog / limites (ajuste conforme sua VM)
MAX_RUNTIME_DEFAULT = 40          # safety extra (s)
ENABLE_CPU_WATCHDOG = False       # <-- DESATIVADO: não mata por uso de CPU alto
MAX_CPU_PERCENT = 80.0            # somente usado se ENABLE_CPU_WATCHDOG = True
MAX_NET_BYTES_DELTA = 40_000_000  # bytes transmitidos máximo durante cenário (aprox 40MB)
WATCHDOG_POLL = 1.0               # intervalo de checagem (s)

# IA wait
MAX_IA_WAIT = 120   # segundos para aguardar nova resposta da IA (ajuste)
IA_POLL_INTERVAL = 3

POST_WAIT = 2  # segundos após término para dar tempo ao detector

# Detecta se 'timeout' existe
TIMEOUT_BIN_EXISTS = bool(shutil.which("timeout"))

# ---------------- CENARIOS ----------------
# ---------------- CENARIOS ----------------
CENARIOS = [
    # ---------------- ATAQUES ----------------
    {"nome": "goldeneye_leve", "comando": f"python3 {GOLDENEYE_PATH} http://{TARGET_IP} -w 10 -s 20", "duracao": 15, "label": "ataque"},
    {"nome": "goldeneye_pesado", "comando": f"python3 {GOLDENEYE_PATH} http://{TARGET_IP} -w 50 -s 100", "duracao": 25, "label": "ataque"},
    {"nome": "torshammer_leve", "comando": f"python2 {TORSHAMMER_PATH} -t {TARGET_IP} -r 10", "duracao": 15, "label": "ataque"},
    {"nome": "torshammer_pesado", "comando": f"python2 {TORSHAMMER_PATH} -t {TARGET_IP} -r 50", "duracao": 25, "label": "ataque"},
    {"nome": "ettercap_arp_spoof", "comando": f"sudo ettercap -T -q -i {NET_IFACE} -M arp:remote /{TARGET_IP}/ /GATEWAY_IP/", "duracao": 20, "label": "ataque"},

    # ---------------- TRÁFEGO NORMAL (realistas e variados) ----------------

    # Requisições leves com ab
    {"nome": "normal_ab_leve", "comando": f"ab -n 20 -c 2 http://{TARGET_IP}/", "duracao": 5, "label": "normal"},

    # Requisições médias com ab
    {"nome": "normal_ab_medio", "comando": f"ab -n 100 -c 5 http://{TARGET_IP}/", "duracao": 10, "label": "normal"},

    # Tráfego intenso com ab
    {"nome": "normal_ab_pesado", "comando": f"ab -n 200 -c 20 http://{TARGET_IP}/", "duracao": 15, "label": "normal"},

    # Tráfego contínuo com curl + delay (requisições simples)
    {"nome": "normal_curl_serial", "comando": f"bash -c 'for i in {{1..20}}; do curl -s http://{TARGET_IP}/ > /dev/null; sleep 0.3; done'", "duracao": 8, "label": "normal"},

    # Curl paralelo (requisições concorrentes)
    {"nome": "normal_curl_concorrente", "comando": f"bash -c 'for i in {{1..10}}; do curl -s http://{TARGET_IP}/ > /dev/null & done; wait'", "duracao": 5, "label": "normal"},

    # Requisições POST simuladas com curl
    {"nome": "normal_post_simulado", "comando": f"bash -c 'for i in {{1..30}}; do curl -s -X POST -d \"key=value$i\" http://{TARGET_IP}/api > /dev/null; sleep 0.2; done'", "duracao": 8, "label": "normal"},

    # Simulação de picos e ociosidade
    {"nome": "normal_picos_osciosidade", "comando": f"bash -c 'curl -s http://{TARGET_IP}/ > /dev/null; sleep 2; curl -s http://{TARGET_IP}/ > /dev/null; sleep 1; curl -s http://{TARGET_IP}/ > /dev/null'", "duracao": 6, "label": "normal"},
]

# ---------------- HELPERS ----------------
def append_jsonl(record: dict):
    os.makedirs(os.path.dirname(OUTPUT_JSONL), exist_ok=True)
    with open(OUTPUT_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def kill_by_name(names):
    # preservado, mas não é chamado por padrão. evite usar sem sudo.
    for name in names:
        try:
            subprocess.run(["pkill", "-f", name], check=False)
        except Exception:
            pass


def fetch_detector_snapshot(timeout=10):
    """
    Retorna o JSON atual do detector ou um dicionário com 'error'.
    """
    try:
        r = requests.get(DETECTOR_URL, timeout=timeout)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"error": "invalid_json_response", "text": r.text}
        else:
            return {"error": f"status_{r.status_code}", "text": r.text}
    except Exception as e:
        return {"error": f"request_exception:{str(e)}"}


def wait_for_new_detector_result(prev_snapshot, max_wait=MAX_IA_WAIT, poll_interval=IA_POLL_INTERVAL):
    """
    Espera até que o detector retorne algo diferente de prev_snapshot.
    Retorna (new_snapshot, waited_seconds, changed_bool).
    """
    start = time.time()
    waited = 0
    prev_serial = json.dumps(prev_snapshot, sort_keys=True, ensure_ascii=False)

    while waited < max_wait:
        cur = fetch_detector_snapshot(timeout=10)
        cur_serial = json.dumps(cur, sort_keys=True, ensure_ascii=False)
        if cur_serial != prev_serial:
            return cur, time.time() - start, True
        time.sleep(poll_interval)
        waited = time.time() - start

    cur = fetch_detector_snapshot(timeout=10)
    return cur, time.time() - start, False


def run_with_watchdog(cmd: str, workdir: str, timeout: int, iface: str,
                      max_cpu=MAX_CPU_PERCENT, max_bytes=MAX_NET_BYTES_DELTA,
                      poll=WATCHDOG_POLL) -> Tuple[int, str]:
    """
    Executa cmd com proteção: timeout e checagem de tráfego.
    CPU watchdog está desativado por padrão (controle via ENABLE_CPU_WATCHDOG).
    Retorna (exit_code, reason).
    """
    final_cmd = cmd
    if TIMEOUT_BIN_EXISTS:
        final_cmd = f"timeout {timeout}s {cmd}"

    try:
        proc = subprocess.Popen(final_cmd, cwd=workdir, shell=True, preexec_fn=os.setsid)
    except Exception as e:
        return -1, f"start_error:{e}"

    pid = proc.pid
    try:
        net0 = psutil.net_io_counters(pernic=True).get(iface)
        tx0 = net0.bytes_sent if net0 else 0
    except Exception:
        tx0 = 0

    start = time.time()
    killed_reason = None

    try:
        while True:
            ret = proc.poll()
            if ret is not None:
                return ret, killed_reason or "finished_normally"

            elapsed = time.time() - start
            if elapsed > timeout + 5:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
                return -9, "hard_timeout_kill"

            # CPU watchdog opcional: só verifica se ENABLE_CPU_WATCHDOG == True
            if ENABLE_CPU_WATCHDOG:
                try:
                    cpu = psutil.cpu_percent(interval=None)
                    if cpu >= max_cpu:
                        killed_reason = f"killed_high_cpu_{cpu:.1f}"
                        try:
                            os.killpg(os.getpgid(pid), signal.SIGTERM)
                            time.sleep(1)
                            if proc.poll() is None:
                                os.killpg(os.getpgid(pid), signal.SIGKILL)
                        except Exception:
                            pass
                        return -9, killed_reason
                except Exception:
                    pass

            # checa bytes enviados - mantido
            try:
                net = psutil.net_io_counters(pernic=True).get(iface)
                tx = net.bytes_sent if net else 0
                if (tx - tx0) > max_bytes:
                    killed_reason = "killed_high_network"
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGTERM)
                        time.sleep(1)
                        if proc.poll() is None:
                            os.killpg(os.getpgid(pid), signal.SIGKILL)
                    except Exception:
                        pass
                    return -9, killed_reason
            except Exception:
                pass

            time.sleep(poll)

    except KeyboardInterrupt:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            proc.kill()
        return -9, "killed_by_user"


# ---------------- RUN SCENARIO ----------------
def run_scenario(cenario: dict):
    nome = cenario["nome"]
    cmd = cenario["comando"]
    dur = cenario.get("duracao", 10)
    label = cenario.get("label", "unknown")
    max_runtime = min(dur + 10, MAX_RUNTIME_DEFAULT)

    timestamp_start = datetime.utcnow().isoformat() + "Z"
    print(f"[{timestamp_start}] Iniciando cenário: {nome} -> `{cmd}` (dur prevista={dur}s)")

    # pega snapshot atual do detector antes de começar
    prev_snapshot = fetch_detector_snapshot()

    # executa com watchdog
    exit_code, reason = run_with_watchdog(cmd, WORKDIR, timeout=max_runtime, iface=NET_IFACE)

    # espera breve e então aguarda por mudança no detector (nova resposta)
    time.sleep(POST_WAIT)
    det_result, waited, changed = wait_for_new_detector_result(prev_snapshot, max_wait=MAX_IA_WAIT, poll_interval=IA_POLL_INTERVAL)

    # NÃO chamamos pkill por nome aqui (evita problemas de permissão).
    # run_with_watchdog já mata o process group que iniciou o comando.
    # Se houver resíduos, mate manualmente com sudo pkill -f <nome> (apenas em emergência).

    registro = {
        "timestamp_start": timestamp_start,
        "timestamp_end": datetime.utcnow().isoformat() + "Z",
        "cenario": nome,
        "label_real": label,
        "cmd": cmd,
        "watchdog_exit_code": exit_code,
        "watchdog_reason": reason,
        "ia_wait_secs": waited,
        "ia_changed": changed,
        "detector_result": det_result
    }

    append_jsonl(registro)
    print(f"[{registro['timestamp_end']}] Cenário {nome} finalizado (reason={reason}) - ia_changed={changed} waited={waited:.1f}s")


# ---------------- MAIN ----------------
def main():
    print("=== Início do benchmark automatizado (ATENÇÃO: somente em ambiente isolado) ===")
    if not os.path.isdir(WORKDIR):
        print(f"WORKDIR {WORKDIR} não existe. Ajuste o WORKDIR no topo do script.")
        sys.exit(1)

    seq = []
    for _ in range(REPETICOES):
        tmp = CENARIOS.copy()
        random.shuffle(tmp)
        seq.extend(tmp)

    try:
        for c in seq:
            run_scenario(c)
            time.sleep(3 + random.uniform(0, 2))
    except KeyboardInterrupt:
        print("Execução interrompida pelo usuário.")
    finally:
        print("=== Execução concluída ===")


if __name__ == "__main__":
    main()
