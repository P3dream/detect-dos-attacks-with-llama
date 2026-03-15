#!/usr/bin/env python3
import subprocess
import json
import requests
import time
from datetime import datetime
import statistics

# ---------------- CONFIGURAÇÃO ----------------
DETECTOR_URL           = "http://192.168.56.1:3000/ia"
INTERFACE              = "enp0s3"
CAPTURE_DURATION       = 5
SLEEP_BETWEEN          = 1.0
SLEEP_BETWEEN_REQUESTS = 2.0
REQUEST_TIMEOUT        = 30
LOG_FILE               = "resultados_fluxos.jsonl"
FLOW_TIMEOUT           = 60

# ---------------- CAPTURA POR JANELA DE TEMPO ----------------
def capture_packets(interface=INTERFACE, duration=CAPTURE_DURATION):
    tshark_command = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
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
        "-e", "frame.len",
        "-e", "tcp.flags.urg",
    ]

    try:
        result = subprocess.run(
            tshark_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=duration + 10
        )
    except subprocess.TimeoutExpired:
        print(f"[{datetime.now().isoformat()}] Timeout na captura.")
        return []
    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Erro ao chamar tshark: {e}")
        return []

    if not result.stdout.strip():
        stderr_text = result.stderr.decode(errors='ignore')
        print(f"[{datetime.now().isoformat()}] Captura vazia: {stderr_text[:200]}")
        return []

    try:
        packets = json.loads(result.stdout.decode(errors='ignore'))
    except json.JSONDecodeError:
        return []

    parsed = []
    for p in packets:
        layers = p.get("_source", {}).get("layers", {})
        time_epoch  = float((layers.get("frame.time_epoch") or [0])[0])
        ip_src      = (layers.get("ip.src")      or [None])[0]
        ip_dst      = (layers.get("ip.dst")      or [None])[0]
        ip_proto    = (layers.get("ip.proto")    or [None])[0]
        tcp_srcport = (layers.get("tcp.srcport") or [None])[0]
        tcp_dstport = (layers.get("tcp.dstport") or [None])[0]
        udp_srcport = (layers.get("udp.srcport") or [None])[0]
        udp_dstport = (layers.get("udp.dstport") or [None])[0]
        length      = int((layers.get("frame.len")      or [0])[0])
        urg_flag    = int((layers.get("tcp.flags.urg") or ["0"])[0])

        srcport = tcp_srcport or udp_srcport
        dstport = tcp_dstport or udp_dstport

        if ip_src and ip_dst:
            parsed.append({
                "time":     time_epoch,
                "ip.src":   ip_src,
                "ip.dst":   ip_dst,
                "protocol": ip_proto,
                "srcport":  srcport,
                "dstport":  dstport,
                "length":   length,
                "urg_flag": urg_flag,
            })

    print(f"[{datetime.now().isoformat()}] {len(parsed)} pacotes capturados em {duration}s")
    return parsed

# ---------------- CRIA FLUXO A PARTIR DE PACOTES ----------------
def create_flow_entry(pkts, key):
    src_ip  = key[0]
    times   = [p["time"]   for p in pkts]
    lengths = [p["length"] for p in pkts]

    fwd_pkts    = [p for p in pkts if p["ip.src"] == src_ip]
    fwd_lengths = [p["length"] for p in fwd_pkts]

    duration = max(times) - min(times) if len(times) > 1 else 0.0

    min_packet_length   = min(lengths)
    avg_fwd_seg_size    = (sum(fwd_lengths) / len(fwd_lengths)) if fwd_lengths else 0.0
    flow_bytes_per_sec  = (sum(lengths)     / duration)         if duration > 0 else 0.0
    urg_flag_count      = sum(p["urg_flag"] for p in pkts)
    fwd_packets_per_sec = (len(fwd_pkts)    / duration)         if duration > 0 else 0.0

    return {
        "Min Packet Length":    round(min_packet_length,   2),
        "Avg Fwd Segment Size": round(avg_fwd_seg_size,    2),
        "Flow Bytes/s":         round(flow_bytes_per_sec,  2),
        "URG Flag Count":       urg_flag_count,
        "Fwd Packets/s":        round(fwd_packets_per_sec, 2),
        "_debug": {
            "src_ip":       key[0],
            "dst_ip":       key[1],
            "src_port":     key[2],
            "dst_port":     key[3],
            "protocol":     key[4],
            "packet_count": len(pkts),
            "duration_s":   round(duration, 4),
        }
    }

# ---------------- AGRUPA PACOTES EM FLUXOS ----------------
def packets_to_flows(packets, timeout=FLOW_TIMEOUT):
    flows        = []
    active_flows = {}

    for pkt in sorted(packets, key=lambda p: p["time"]):
        key      = (pkt["ip.src"], pkt["ip.dst"], pkt["srcport"], pkt["dstport"], pkt["protocol"])
        pkt_time = pkt["time"]

        if key in active_flows:
            if pkt_time - active_flows[key]["last_time"] > timeout:
                flows.append(create_flow_entry(active_flows[key]["pkts"], key))
                active_flows[key] = {"pkts": [pkt], "last_time": pkt_time}
            else:
                active_flows[key]["pkts"].append(pkt)
                active_flows[key]["last_time"] = pkt_time
        else:
            active_flows[key] = {"pkts": [pkt], "last_time": pkt_time}

    for key, data in active_flows.items():
        flows.append(create_flow_entry(data["pkts"], key))

    return flows

# ---------------- ENVIO PARA DETECTOR ----------------
def send_flows(flows, url=DETECTOR_URL):
    if not flows:
        return

    for flow in flows:
        payload = {k: v for k, v in flow.items() if k != "_debug"}

        d = flow.get("_debug", {})
        print(f"[{datetime.now().isoformat()}] Enviando fluxo: "
              f"{d.get('src_ip')}:{d.get('src_port')} → {d.get('dst_ip')}:{d.get('dst_port')} "
              f"| pkts={d.get('packet_count')} dur={d.get('duration_s')}s "
              f"| Bytes/s={flow['Flow Bytes/s']} FwdPkts/s={flow['Fwd Packets/s']}")

        try:
            response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                response_json = response.json()
                print(f"[{datetime.now().isoformat()}] ✅ Resultado: {response_json}")
                with open(LOG_FILE, "a") as f:
                    f.write(json.dumps({
                        "timestamp": datetime.now().isoformat(),
                        "flow":      flow,
                        "response":  response_json
                    }, ensure_ascii=False) + "\n")
            else:
                print(f"[{datetime.now().isoformat()}] ❌ Status {response.status_code}: {response.text[:200]}")
        except requests.exceptions.RequestException as e:
            print(f"[{datetime.now().isoformat()}] ❌ Erro de conexão: {e}")

        time.sleep(SLEEP_BETWEEN_REQUESTS)

# ---------------- LOOP PRINCIPAL ----------------
def main_loop():
    print(f"=== Captura por janelas de {CAPTURE_DURATION}s na interface {INTERFACE} ===")
    try:
        while True:
            packets = capture_packets()
            if packets:
                flows = packets_to_flows(packets)
                send_flows(flows)
            else:
                print(f"[{datetime.now().isoformat()}] Nenhum pacote capturado.")
            time.sleep(SLEEP_BETWEEN)
    except KeyboardInterrupt:
        print("\n=== Interrompido pelo usuário ===")

if __name__ == "__main__":
    main_loop()