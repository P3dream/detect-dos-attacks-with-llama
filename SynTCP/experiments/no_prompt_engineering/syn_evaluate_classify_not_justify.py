import pandas as pd
import requests
import json
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

CSV_PATH = "datasets/Syn_balanceado_50_50.csv"
API_URL = "http://localhost:3000/ia"

print("🔍 Lendo dataset...")
df = pd.read_csv(CSV_PATH, usecols=[
    "Flow Duration",
    "Flow Packets/s",
    "Avg Fwd Segment Size",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Label"
], low_memory=False)

# --- Limpar nomes das colunas ---
df.columns = df.columns.str.strip()

# --- Normalizar coluna Label ---
df["Label"] = df["Label"].astype(str).str.strip()

print("Colunas detectadas:", df.columns.tolist())

# --- Filtrar BENIGN e SYN ---
benign_df = df[df["Label"] == "BENIGN"]
syn_df = df[df["Label"].str.contains("Syn", case=False)]

print(f"BENIGN: {len(benign_df)}")
print(f"SYN: {len(syn_df)}")

# --- Selecionar 50 de cada para teste ---
benign_sample = benign_df.sample(n=50, random_state=42)
syn_sample = syn_df.sample(n=50, random_state=42)

# --- Criar dataset final de 100 amostras ---
test_df = pd.concat([
    benign_sample.assign(true_label="BENIGN"),
    syn_sample.assign(true_label="SYN")
]).sample(frac=1, random_state=42).reset_index(drop=True)

y_true = []
y_pred = []
log_entries = []

print("🚀 Enviando 100 fluxos para o modelo...")

def build_flow_json(row):
    # Apenas as colunas que o LLM precisa, sem Label
    return {
        "duration": row["Flow Duration"],
        "flow_packets_per_second": row["Flow Packets/s"],
        "avg_fwd_segment_size": row["Avg Fwd Segment Size"],
        "avg_packet_size": row["Average Packet Size"],
        "init_win_bytes_forward": row["Init_Win_bytes_forward"]
    }

total_flows = len(test_df)  # 100
progress_step = total_flows // 5  # cada 20%

for idx, row in test_df.iterrows():
    flow_data = build_flow_json(row)

    try:
        response = requests.post(API_URL, json=[flow_data])
        result = response.json()

        # ✅ Agora esperamos diretamente "SYN" ou "BENIGN"
        predicted = result["result"].get("predicted_label", "ERROR")

    except Exception as e:
        print(f"⚠️ Erro ao enviar fluxo {idx}: {e}")
        predicted = "ERROR"

    y_true.append(row["true_label"])
    y_pred.append(predicted)

    log_entries.append({
        "flow_id": idx,
        "true_label": row["true_label"],
        "predicted": predicted,
        "raw_response": result if 'result' in locals() else str(e)
    })

    # --- Print de progresso a cada 20% ---
    if (idx + 1) % progress_step == 0 or (idx + 1) == total_flows:
        pct = int((idx + 1) / total_flows * 100)
        print(f"📤 Progresso: {idx + 1}/{total_flows} fluxos enviados ({pct}%)")

# --- Salvar logs ---
with open("syn_test_log.json", "w") as f:
    json.dump(log_entries, f, indent=4)

print("📁 Logs salvos em syn_test_log.json")

# --- Matriz de Confusão ---
cm = confusion_matrix(y_true, y_pred, labels=["BENIGN", "SYN"])
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["BENIGN", "SYN"])

plt.figure(figsize=(6, 6))
disp.plot(values_format='d')
plt.title("Matriz de Confusão – llama3.2:1b vs SYN Dataset")
plt.savefig("confusion_matrix.png")
plt.close()

print("📊 Matriz de confusão salva como confusion_matrix.png")
print("✅ Avaliação concluída!")
