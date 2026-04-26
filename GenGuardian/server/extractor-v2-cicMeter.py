#!/usr/bin/env python3
import subprocess
import pandas as pd
import requests
import os
import time
import datetime

# ---------------- CONFIGURAÇÃO ----------------
INTERFACE      = "enp0s3"
CAPTURE_SECS   = 10
BASE_DIR       = "/home/pedro/detect-dos-attacks-with-llama"
PCAP_DIR       = f"{BASE_DIR}/captures"
CSV_OUTPUT_DIR = f"{BASE_DIR}/flows_output"
CIC_JAR        = f"{BASE_DIR}/CICFlowMeter/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
CIC_LIB        = f"{BASE_DIR}/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425"
DETECTOR_URL   = "http://192.168.56.1:3000/ia"

FEATURE_MAP = {
    "Min Packet Length":    "Packet Length Min",
    "Avg Fwd Segment Size": "Fwd Segment Size Avg",
    "Flow Bytes/s":         "Flow Bytes/s",
    "URG Flag Count":       "URG Flag Count",
    "Fwd Packets/s":        "Fwd Packets/s"
}

# ---------------- FUNÇÕES ----------------
def capturar_pcap(duracao=CAPTURE_SECS):
    os.makedirs(PCAP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"capture_{ts}.pcap")

    print(f"[*] Capturando {duracao}s em {INTERFACE}...")
    subprocess.run([
        "sudo", "timeout", str(duracao),
        "tcpdump", "-i", INTERFACE, "-w", pcap_path, "-q"
    ])
    print(f"[*] PCAP salvo: {pcap_path}")
    return pcap_path

def gerar_csv(pcap_path):
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

    subprocess.run([
        "sudo", "java",
        "-Djava.awt.headless=true",
        f"-Djava.library.path={CIC_LIB}",
        "-cp", CIC_JAR,
        "cic.cs.unb.ca.ifm.Cmd",
        pcap_path,
        CSV_OUTPUT_DIR
    ], check=True)

    csvs = sorted(
        [f for f in os.listdir(CSV_OUTPUT_DIR) if f.endswith(".csv")],
        key=lambda f: os.path.getmtime(os.path.join(CSV_OUTPUT_DIR, f))
    )
    if not csvs:
        raise FileNotFoundError("Nenhum CSV gerado")
    return os.path.join(CSV_OUTPUT_DIR, csvs[-1])

def ler_fluxos(csv_path):
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    faltando = [v for v in FEATURE_MAP.values() if v not in df.columns]
    if faltando:
        print(f"[!] Colunas faltando: {faltando}")
        print(f"[!] Colunas disponíveis: {list(df.columns)}")
        return []

    fluxos = []
    for _, row in df.iterrows():
        fluxo = {
            nome_modelo: row[nome_csv]
            for nome_modelo, nome_csv in FEATURE_MAP.items()
        }
        fluxos.append(fluxo)

    return fluxos

def enviar_fluxos(fluxos):
    for i, fluxo in enumerate(fluxos):
        try:
            resp = requests.post(DETECTOR_URL, json=fluxo, timeout=5)
            print(f"[{i+1}/{len(fluxos)}] {resp.status_code} | {resp.text}")
        except requests.exceptions.RequestException as e:
            print(f"[{i+1}/{len(fluxos)}] Erro: {e}")

# ---------------- LOOP CONTÍNUO ----------------
if __name__ == "__main__":
    print("[*] GenGuardian pipeline iniciado")
    while True:
        try:
            pcap = capturar_pcap(CAPTURE_SECS)

            print("[*] Processando com CICFlowMeter...")
            csv = gerar_csv(pcap)
            print(f"[*] CSV: {csv}")

            fluxos = ler_fluxos(csv)
            print(f"[*] {len(fluxos)} fluxos para análise")

            if fluxos:
                enviar_fluxos(fluxos)
            else:
                print("[*] Nenhum fluxo gerado nessa janela")

        except KeyboardInterrupt:
            print("\n[*] Interrompido")
            break
        except Exception as e:
            print(f"[!] Erro: {e}")
            time.sleep(5)
