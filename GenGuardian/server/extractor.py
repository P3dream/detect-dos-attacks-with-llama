#!/usr/bin/env python3
import subprocess
import json
import requests
import time
from datetime import datetime
from urllib.parse import urljoin

# ---------------- CONFIGURAÇÃO ----------------
DETECTOR_URL = "http://192.168.56.1:3000/ia"
INTERFACE = "enp0s3"
PACKET_COUNT = 50           # quantos pacotes capturar por vez
SLEEP_BETWEEN = 1.0         # segundos entre capturas
REQUEST_TIMEOUT = 30
LOG_FILE = "resultados_deteccao.jsonl"
TARGET_IP = "192.168.56.3"  # IP do servidor do site
TARGET_PORT = 80            # HTTP

# ---------------- CAPTURA DE PACOTES ----------------
def capture_packets(interface="enp0s3", packet_count=50, target_ip=None, target_port=80):
    """
    Captura pacotes HTTP (requests) e tenta extrair a rota/URL destino e, se houver, o body de POST.
    Usa reassembly TCP/HTTP para reduzir campos null.
    """
    # Monta display filter: apenas http.request ao target (se target_ip fornecido)
    if target_ip:
        display_filter = f"http.request && ip.dst == {target_ip} && tcp.port == {target_port}"
    else:
        display_filter = f"http.request && tcp.port == {target_port}"

    tshark_command = [
        "tshark",
        "-i", interface,
        "-c", str(packet_count),
        "-s", "0",  # captura o pacote inteiro (sem truncar)
        "-T", "json",
        "-Y", display_filter,
        # Força reassembly para que o dissector HTTP consiga montar headers/body
        "-o", "tcp.desegment_tcp_streams:TRUE",
        "-o", "http.desegment_headers:TRUE",
        "-o", "http.desegment_body:TRUE",
        # Campos úteis
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "http.request.method",
        "-e", "http.request.line",
        "-e", "http.request.uri",
        "-e", "http.request.full_uri",
        "-e", "http.host",
        "-e", "http.user_agent",
        "-e", "http.content_type",
        "-e", "http.file_data",          # frequentemente contém body de POST
        "-e", "http.request.version",
    ]

    try:
        result = subprocess.run(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Erro ao chamar tshark: {e}")
        return []

    if result.returncode != 0:
        stderr_text = result.stderr.decode(errors='ignore')
        print(f"[{datetime.now().isoformat()}] Erro na captura (retcode {result.returncode}): {stderr_text}")
        return []

    try:
        packets = json.loads(result.stdout.decode(errors='ignore'))
    except json.JSONDecodeError as e:
        print(f"[{datetime.now().isoformat()}] Erro JSON do tshark: {e}")
        return []

    parsed = []
    for p in packets:
        layers = p.get("_source", {}).get("layers", {})

        time_field = (layers.get("frame.time") or [None])[0]
        ip_src = (layers.get("ip.src") or [None])[0]
        ip_dst = (layers.get("ip.dst") or [None])[0]
        tcp_srcport = (layers.get("tcp.srcport") or [None])[0]
        tcp_dstport = (layers.get("tcp.dstport") or [None])[0]

        http_method = (layers.get("http.request.method") or [None])[0]
        http_req_line = (layers.get("http.request.line") or [None])[0]
        http_uri = (layers.get("http.request.uri") or [None])[0]
        http_full = (layers.get("http.request.full_uri") or [None])[0]
        http_host = (layers.get("http.host") or [None])[0]
        http_user_agent = (layers.get("http.user_agent") or [None])[0]
        http_content_type = (layers.get("http.content_type") or [None])[0]
        http_file_data = (layers.get("http.file_data") or [None])[0]  # pode conter body do POST
        http_version = (layers.get("http.request.version") or [None])[0]

        # Reconstrói URL: prefira full_uri, senão host + uri. Se host for IP, fica ok.
        reconstructed_url = None
        if http_full and http_full != "":
            reconstructed_url = http_full
        elif http_host and http_uri:
            # pode ser host:port em http_host (por ex. myhost:8080)
            # garante esquema http porque estamos na porta 80 (ou se porta != 80, ainda assim usa http)
            scheme = "http"
            # se o http_host já contém http:// ou https:// (raro), evita duplicar
            if http_host.startswith("http://") or http_host.startswith("https://"):
                reconstructed_url = urljoin(http_host, http_uri or "")
            else:
                reconstructed_url = f"{scheme}://{http_host}{http_uri or ''}"
        elif http_uri:
            reconstructed_url = http_uri  # sem host disponível

        # Normaliza body: http.file_data vem geralmente hex/text; deixamos raw e também tentamos truncar para segurança de log
        body_raw = None
        if http_file_data:
            body_raw = http_file_data  # pode ser grande, contem o corpo do POST (raw)
        # Monta registro
        entry = {
            "time": time_field,
            "ip.src": ip_src,
            "ip.dst": ip_dst,
            "tcp.srcport": tcp_srcport,
            "tcp.dstport": tcp_dstport,
            "http.method": http_method,
            "http.request_line": http_req_line,
            "http.uri": http_uri,
            "http.full_uri": http_full,
            "http.host": http_host,
            "http.user_agent": http_user_agent,
            "http.version": http_version,
            "http.content_type": http_content_type,
            "http.reconstructed_url": reconstructed_url,
            # body (se houver). ATENÇÃO: pode conter dados sensíveis
            "http.body_raw": body_raw,
        }
        parsed.append(entry)

    return parsed

# ---------------- ENVIO PARA DETECTOR ----------------
def send_data_to_url(data, url=DETECTOR_URL):
    if not data:
        return
    try:
        response = requests.post(url, json=data, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            try:
                response_json = response.json()
                print(f"[{datetime.now().isoformat()}] Dados enviados com sucesso. {len(data)} pacotes")
                # salva no log .jsonl
                with open(LOG_FILE, "a") as f:
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "packets_count": len(data),
                        "response": response_json
                    }
                    f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
            except Exception:
                print(f"[{datetime.now().isoformat()}] Resposta não-JSON: {response.text[:200]}")
        else:
            print(f"[{datetime.now().isoformat()}] Falha ao enviar. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now().isoformat()}] Erro ao enviar dados: {e}")

# ---------------- LOOP PRINCIPAL ----------------
def main_loop():
    print("=== Iniciando captura contínua. Pressione Ctrl-C para parar. ===")
    try:
        while True:
            packets = capture_packets(interface=INTERFACE, packet_count=PACKET_COUNT,
                                      target_ip=TARGET_IP, target_port=TARGET_PORT)
            if packets:
                send_data_to_url(packets)
            else:
                print(f"[{datetime.now().isoformat()}] Nenhum pacote capturado.")
            time.sleep(SLEEP_BETWEEN)
    except KeyboardInterrupt:
        print("\n=== Execução interrompida pelo usuário (Ctrl-C). Encerrando. ===")

if __name__ == "__main__":
    main_loop()
