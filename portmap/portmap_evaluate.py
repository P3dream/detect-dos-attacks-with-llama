import pandas as pd
import requests
import json
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

CSV_PATH = "Portmap.csv"
API_URL = "http://localhost:3000/ia"

print("🔍 Lendo dataset...")
df = pd.read_csv(CSV_PATH, low_memory=False)

# --- Limpando nomes das colunas ---
df.columns = df.columns.str.strip()

# --- Normalizando coluna Label ---
df["Label"] = df["Label"].astype(str).str.strip()

print("Colunas detectadas:", df.columns.tolist())

# --- Filtrar BENIGN e PORTMAP ---
benign_df = df[df["Label"] == "BENIGN"]
portmap_df = df[df["Label"].str.contains("Portmap", case=False)]

print(f"BENIGN: {len(benign_df)}")
print(f"PORTMAP: {len(portmap_df)}")

# --- Selecionar 50 de cada ---
benign_sample = benign_df.sample(500, random_state=42)
portmap_sample = portmap_df.sample(500, random_state=42)

# --- Criar dataset final 100 amostras ---
test_df = pd.concat([
    benign_sample.assign(true_label="BENIGN"),
    portmap_sample.assign(true_label="ATTACK")
]).sample(frac=1, random_state=42)

y_true = []
y_pred = []

log_entries = []

print("🚀 Enviando 100 fluxos para o modelo...")

def build_flow_json(row):
    packet_count = row['Total Fwd Packets'] + row['Total Backward Packets']
    total_bytes = row['Total Length of Fwd Packets'] + row['Total Length of Bwd Packets']
    avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0

    return {
        "src_ip": row['Source IP'],
        "dst_ip": row['Destination IP'],
        "src_port": int(row['Source Port']),
        "dst_port": int(row['Destination Port']),
        "protocol": "TCP" if row['Protocol']==6 else "UDP" if row['Protocol']==17 else "Other",
        "duration": row['Flow Duration'],
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_packet_size": avg_packet_size,
        "flow_bytes_per_second": row['Flow Bytes/s'],
        "flow_packets_per_second": row['Flow Packets/s'],
        "iat_mean": row['Flow IAT Mean'],
        "iat_std": row['Flow IAT Std']
    }

for idx, row in test_df.iterrows():
    flow_data = build_flow_json(row)

    try:
        response = requests.post(API_URL, json=[flow_data])
        result = response.json()

        prob = result["result"]["dos_attack_probability"]
        predicted = "ATTACK" if prob >= 70 else "BENIGN"

    except Exception as e:
        print(f"⚠️ Erro ao enviar fluxo {row.get('Flow ID', idx)}: {e}")
        prob = None
        predicted = "ERROR"

    y_true.append(row["true_label"])
    y_pred.append(predicted)

    log_entries.append({
        "flow_id": row.get("Flow ID", idx),
        "true_label": row["true_label"],
        "predicted": predicted,
        "probability": prob,
        "raw_response": result if 'result' in locals() else str(e)
    })

# --- Salvar logs ---
with open("portmap_test_log.json", "w") as f:
    json.dump(log_entries, f, indent=4)

print("📁 Logs salvos em portmap_test_log.json")

# --- Matriz de Confusão ---
cm = confusion_matrix(y_true, y_pred, labels=["BENIGN", "ATTACK"])
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["BENIGN", "ATTACK"])

plt.figure(figsize=(6, 6))
disp.plot(values_format='d')
plt.title("Matriz de Confusão – Llama vs Portmap Dataset")
plt.savefig("confusion_matrix.png")
plt.close()

print("📊 Matriz de confusão salva como confusion_matrix.png")
print("✅ Avaliação concluída!")
