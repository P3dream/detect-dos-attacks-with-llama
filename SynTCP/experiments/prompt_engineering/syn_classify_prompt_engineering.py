import pandas as pd
import requests
import json
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

CSV_PATH = r"C:\projects\detect-dos-attacks-with-llama\SynTCP\datasets\Syn_balanceado_50_50.csv"
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

# --- Selecionar 50 de cada ---
benign_sample = benign_df.sample(n=50, random_state=42)
syn_sample = syn_df.sample(n=50, random_state=42)

# --- Criar dataset final ---
test_df = pd.concat([
    benign_sample.assign(true_label="BENIGN"),
    syn_sample.assign(true_label="SYN")
]).sample(frac=1, random_state=42).reset_index(drop=True)

y_true = []
y_pred = []
log_entries = []

print("🚀 Enviando 100 fluxos para o modelo...")

def build_flow_prompt(row):
    return f"""
Analyze the following network flow features and estimate the probability of a SYN-based DoS attack.

Feature descriptions:
- Flow Duration: Total duration of the network flow in microseconds.
- Flow Packets per Second: Number of packets transmitted per second in this flow.
- Average Forward Segment Size: Average size of forward TCP segments in bytes.
- Average Packet Size: Mean size of packets within the flow in bytes.
- Initial Forward Window Bytes: Initial TCP window size announced by the forward direction.

Flow data:
- Flow Duration: {row["Flow Duration"]}
- Flow Packets per Second: {row["Flow Packets/s"]}
- Average Forward Segment Size: {row["Avg Fwd Segment Size"]}
- Average Packet Size: {row["Average Packet Size"]}
- Initial Forward Window Bytes: {row["Init_Win_bytes_forward"]}

You must respond ONLY with a valid JSON object:

{{
  "dos_attack_probability": integer (0-100),
  "justification": "short technical explanation"
}}

Where:
- 0 = definitely benign
- 100 = highly likely SYN DoS attack
- Values >= 70 indicate an attack
"""

total_flows = len(test_df)
progress_step = total_flows // 5

for idx, row in test_df.iterrows():
    flow_prompt = build_flow_prompt(row)

    try:
        response = requests.post(API_URL, json=[flow_prompt])
        result = response.json()

        prob = result.get("result", {}).get("dos_attack_probability", 0)

        try:
            prob = float(prob)
        except:
            prob = 0

        predicted = "SYN" if prob >= 70 else "BENIGN"

        justification = result.get("result", {}).get("justification", "")

    except Exception as e:
        print(f"⚠️ Erro ao enviar fluxo {idx}: {e}")
        predicted = "ERROR"
        prob = 0
        justification = "Request failed"
        result = {"error": str(e)}

    y_true.append(row["true_label"])
    y_pred.append(predicted)

    log_entries.append({
        "flow_id": idx,
        "true_label": row["true_label"],
        "predicted": predicted,
        "dos_attack_probability": prob,
        "justification": justification,
        "raw_response": result
    })

    # --- Progresso ---
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
plt.title("Matriz de Confusão Prompt Engineering– llama3.2:1b vs SYN Dataset")
plt.savefig("confusion_matrix.png")
plt.close()

print("📊 Matriz de confusão salva como confusion_matrix.png")
print("✅ Avaliação concluída!")