#!/usr/bin/env python3
import subprocess
import json
import requests
import time
from datetime import datetime
from collections import defaultdict
import statistics

# ---------------- CONFIGURAÇÃO ----------------
DETECTOR_URL = "http://192.168.56.1:3000/ia"
INTERFACE = "enp0s3"
PACKET_COUNT = 50
SLEEP_BETWEEN = 1.0
REQUEST_TIMEOUT = 30
LOG_FILE = "resultados_fluxos.jsonl"
FLOW_TIMEOUT = 60  # segundos de inatividade para fechar fluxo

# ---------------- CAPTURA DE PACOTES ----------------
def capture_packets(interface=INTERFACE, packet_count=PACKET_COUNT):
    tshark_command = [
        "tshark",
        "-i", interface,
        "-c", str(packet_count),
        "-s", "0",
        "-T", "json",
        "-Y", "ip",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.len"
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
        time_epoch = float((layers.get("frame.time_epoch") or [0])[0])
        ip_src = (layers.get("ip.src") or [None])[0]
        ip_dst = (layers.get("ip.dst") or [None])[0]
        ip_proto = (layers.get("ip.proto") or [None])[0]
        tcp_srcport = (layers.get("tcp.srcport") or [None])[0]
        tcp_dstport = (layers.get("tcp.dstport") or [None])[0]
        udp_srcport = (layers.get("udp.srcport") or [None])[0]
        udp_dstport = (layers.get("udp.dstport") or [None])[0]
        length = int((layers.get("frame.len") or [0])[0])

        srcport = tcp_srcport or udp_srcport
        dstport = tcp_dstport or udp_dstport

        parsed.append({
            "time": time_epoch,
            "ip.src": ip_src,
            "ip.dst": ip_dst,
            "protocol": ip_proto,
            "srcport": srcport,
            "dstport": dstport,
            "length": length
        })

    return parsed

# ---------------- CRIA FLUXO A PARTIR DE PACOTES ----------------
def create_flow_entry(pkts, key):
    times = [p["time"] for p in pkts]
    lengths = [p["length"] for p in pkts]
    times_sorted = sorted(times)

    iat = [t2 - t1 for t1, t2 in zip(times_sorted[:-1], times_sorted[1:])]
    iat_mean = statistics.mean(iat) if iat else 0
    iat_std = statistics.stdev(iat) if len(iat) > 1 else 0
    duration = max(times) - min(times) if len(times) > 1 else 0

    return {
        "src_ip": key[0],
        "dst_ip": key[1],
        "src_port": key[2],
        "dst_port": key[3],
        "protocol": key[4],
        "start_time": min(times),
        "end_time": max(times),
        "duration": duration,
        "packet_count": len(pkts),
        "total_bytes": sum(lengths),
        "avg_packet_size": sum(lengths)/len(lengths) if len(lengths) > 0 else 0,
        "flow_bytes_per_second": sum(lengths)/duration if duration > 0 else 0,
        "flow_packets_per_second": len(pkts)/duration if duration > 0 else 0,
        "iat_mean": iat_mean,
        "iat_std": iat_std
    }

# ---------------- AGRUPA PACOTES EM FLUXOS COM TIMEOUT ----------------
def packets_to_flows(packets, timeout=FLOW_TIMEOUT):
    flows = []
    active_flows = {}  # key -> {"pkts": [...], "last_time": t_last}

    for pkt in packets:
        key = (pkt["ip.src"], pkt["ip.dst"], pkt["srcport"], pkt["dstport"], pkt["protocol"])
        pkt_time = pkt["time"]

        if key in active_flows:
            last_time = active_flows[key]["last_time"]
            if pkt_time - last_time > timeout:
                flows.append(create_flow_entry(active_flows[key]["pkts"], key))
                active_flows[key] = {"pkts": [pkt], "last_time": pkt_time}
            else:
                active_flows[key]["pkts"].append(pkt)
                active_flows[key]["last_time"] = pkt_time
        else:
            active_flows[key] = {"pkts": [pkt], "last_time": pkt_time}

    # Fecha todos os fluxos restantes
    for key, data in active_flows.items():
        flows.append(create_flow_entry(data["pkts"], key))

    return flows

# ---------------- ENVIO PARA DETECTOR ----------------
def send_data_to_url(data, url=DETECTOR_URL):
    if not data:
        return
    try:
        response = requests.post(url, json=data, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            try:
                response_json = response.json()
                print(f"[{datetime.now().isoformat()}] Fluxos enviados: {len(data)}")
                with open(LOG_FILE, "a") as f:
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "flows_count": len(data),
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
    print("=== Iniciando captura contínua de fluxos com timeout ===")
    try:
        while True:
            packets = capture_packets()
            if packets:
                flows = packets_to_flows(packets)
                send_data_to_url(flows)
            else:
                print(f"[{datetime.now().isoformat()}] Nenhum pacote capturado.")
            time.sleep(SLEEP_BETWEEN)
    except KeyboardInterrupt:
        print("\n=== Execução interrompida pelo usuário ===")

if __name__ == "__main__":
    main_loop()
