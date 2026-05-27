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

# IPs que NUNCA serão bloqueados (gateway, DNS, servidor da API, loopback)
IP_WHITELIST = {
    "127.0.0.1",
    "192.168.56.1",   # servidor da API de detecção
    "8.8.8.8",
    "8.8.4.4",
}

FEATURE_MAP = {
    "Min Packet Length":    "Packet Length Min",
    "Avg Fwd Segment Size": "Fwd Segment Size Avg",
    "Flow Bytes/s":         "Flow Bytes/s",
    "URG Flag Count":       "URG Flag Count",
    "Fwd Packets/s":        "Fwd Packets/s",
    # Coluna com IP de origem — ajuste o nome se o seu CSV usar outro cabeçalho
    "_src_ip":              "Src IP",
}

# Conjunto em memória de IPs já bloqueados (evita chamadas repetidas ao iptables)
_ips_bloqueados: set = set()

# ---------------- IPTABLES ----------------

def _iptables(args: list[str]) -> tuple[int, str]:
    """Executa um comando iptables com sudo e retorna (returncode, stderr)."""
    result = subprocess.run(
        ["sudo", "iptables"] + args,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stderr.strip()


def bloquear_ip(ip: str, classificacao: str) -> None:
    """
    Adiciona regra DROP no iptables para o IP de origem, caso ainda não esteja
    bloqueado e não esteja na whitelist.
    """
    if not ip or ip == "N/A":
        return

    if ip in IP_WHITELIST:
        print(f"  [whitelist] {ip} ignorado (whitelist)")
        return

    if ip in _ips_bloqueados:
        print(f"  [iptables] {ip} já estava bloqueado")
        return

    # Verifica se a regra já existe no kernel (segurança extra entre reinicializações)
    rc, _ = _iptables(["-C", "INPUT", "-s", ip, "-j", "DROP"])
    if rc == 0:
        # Regra já existe — apenas registra localmente
        _ips_bloqueados.add(ip)
        print(f"  [iptables] regra já existia para {ip}")
        return

    rc, err = _iptables(["-A", "INPUT", "-s", ip, "-j", "DROP"])
    if rc == 0:
        _ips_bloqueados.add(ip)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [iptables] BLOQUEADO {ip} | motivo: {classificacao} | {ts}")
    else:
        print(f"  [iptables] FALHA ao bloquear {ip}: {err}")
        print("  [iptables] Verifique se sudo iptables está permitido sem senha")
        print("  [iptables] Dica: adicione ao sudoers ->  pedro ALL=(ALL) NOPASSWD: /sbin/iptables")


def listar_bloqueados() -> None:
    """Exibe os IPs bloqueados na sessão atual."""
    if _ips_bloqueados:
        print(f"[*] IPs bloqueados nesta sessão ({len(_ips_bloqueados)}): {', '.join(sorted(_ips_bloqueados))}")
    else:
        print("[*] Nenhum IP bloqueado nesta sessão")

# ---------------- CAPTURA & FLUXOS ----------------

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

    # Colunas obrigatórias para o modelo (exclui coluna interna _src_ip)
    colunas_modelo = {k: v for k, v in FEATURE_MAP.items() if not k.startswith("_")}
    faltando = [v for v in colunas_modelo.values() if v not in df.columns]
    if faltando:
        print(f"[!] Colunas faltando: {faltando}")
        print(f"[!] Colunas disponíveis: {list(df.columns)}")
        return []

    # Coluna de IP de origem (opcional — pode não existir em todos os CSVs)
    src_ip_col = FEATURE_MAP.get("_src_ip", "Src IP")
    tem_ip = src_ip_col in df.columns

    fluxos = []
    for _, row in df.iterrows():
        fluxo = {
            nome_modelo: row[nome_csv]
            for nome_modelo, nome_csv in colunas_modelo.items()
        }
        # Anexa IP de origem como metadado (não enviado ao modelo)
        fluxo["_src_ip"] = str(row[src_ip_col]).strip() if tem_ip else "N/A"
        fluxos.append(fluxo)

    return fluxos

# ---------------- ENVIO & BLOQUEIO ----------------

def enviar_fluxos(fluxos):
    for i, fluxo in enumerate(fluxos):
        src_ip = fluxo.pop("_src_ip", "N/A")  # remove metadado antes de enviar

        try:
            resp = requests.post(DETECTOR_URL, json=fluxo, timeout=5)
            status = resp.status_code
            body   = resp.text

            # Tenta extrair classificação da resposta JSON
            classificacao = "UNKNOWN"
            try:
                data = resp.json()
                # Estrutura esperada: {"exec_id": "...", "result": {"classification": "BENIGN"|"UDPLag", ...}}
                classificacao = (
                    data.get("result", {}).get("classification", "UNKNOWN")
                    or data.get("classification", "UNKNOWN")
                )
            except Exception:
                pass  # body não é JSON válido

            print(f"[{i+1}/{len(fluxos)}] IP={src_ip} | {status} | classificação={classificacao}")

            # Bloqueia se não for BENIGN
            if classificacao.upper() != "BENIGN":
                bloquear_ip(src_ip, classificacao)

        except requests.exceptions.RequestException as e:
            print(f"[{i+1}/{len(fluxos)}] IP={src_ip} | Erro de conexão: {e}")

# ---------------- LOOP CONTÍNUO ----------------

if __name__ == "__main__":
    print("[*] GenGuardian pipeline iniciado")
    print(f"[*] Whitelist de IPs protegidos: {IP_WHITELIST}")

    # Dica de sudoers na inicialização
    print("[*] Certifique-se de que o usuário tem permissão para iptables sem senha:")
    print("    sudo visudo  →  pedro ALL=(ALL) NOPASSWD: /sbin/iptables")

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
                listar_bloqueados()
            else:
                print("[*] Nenhum fluxo gerado nessa janela")
        except KeyboardInterrupt:
            print("\n[*] Interrompido pelo usuário")
            listar_bloqueados()
            break
        except Exception as e:
            print(f"[!] Erro: {e}")
            time.sleep(5)
