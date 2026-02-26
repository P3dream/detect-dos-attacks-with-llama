import json
import requests
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report
import matplotlib.pyplot as plt

TEST_DATASET_PATH = r"C:\projects\detect-dos-attacks-with-llama\SynTCP\fine-tuning\test_dataset.jsonl"
API_URL = "http://localhost:3000/ia"

print("🔍 Lendo test_dataset.jsonl...")

records = []
with open(TEST_DATASET_PATH, encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))

print(f"✅ Total de exemplos: {len(records)}")

y_true = []
y_pred = []
log_entries = []
errors = 0

records =  records[:500]

total = len(records)
progress_step = total // 5

print(f"🚀 Enviando {total} fluxos para o modelo...\n")

for idx, r in enumerate(records):
    # Label real a partir do score do dataset
    expected_score = json.loads(r["messages"][2]["content"])["dos_attack_probability"]
    true_label = "SYN" if expected_score == 95 else "BENIGN"

    # Prompt original do registro
    user_content = r["messages"][1]["content"]

    try:
        response = requests.post(API_URL, json=[user_content], timeout=30)
        result = response.json()

        prob = result.get("result", {}).get("dos_attack_probability", 0)
        try:
            prob = float(prob)
        except:
            prob = 0

        predicted = "SYN" if prob >= 70 else "BENIGN"

    except Exception as e:
        print(f"⚠️ Erro no fluxo {idx}: {e}")
        predicted = "BENIGN"
        prob = 0
        result = {"error": str(e)}
        errors += 1

    y_true.append(true_label)
    y_pred.append(predicted)

    log_entries.append({
        "flow_id": idx,
        "true_label": true_label,
        "predicted": predicted,
        "dos_attack_probability": prob,
        "raw_response": result
    })

    if (idx + 1) % progress_step == 0 or (idx + 1) == total:
        pct = int((idx + 1) / total * 100)
        print(f"📤 Progresso: {idx + 1}/{total} ({pct}%)")

# --- Salvar logs ---
with open("syn_test_log_finetuned.json", "w") as f:
    json.dump(log_entries, f, indent=4)

print(f"\n📁 Logs salvos em syn_test_log_finetuned.json")
print(f"⚠️  Erros de requisição: {errors}")

# --- Resultados ---
print(f"\n📊 Resultado final:")
print(classification_report(y_true, y_pred, labels=["BENIGN", "SYN"]))

# --- Matriz de Confusão ---
cm = confusion_matrix(y_true, y_pred, labels=["BENIGN", "SYN"])
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["BENIGN", "SYN"])

plt.figure(figsize=(6, 6))
disp.plot(values_format='d')
plt.title("Matriz de Confusão — Llama 3.2-1B Finetuned vs SYN Dataset")
plt.savefig("confusion_matrix_finetuned.png")
plt.close()

print("📊 Matriz salva como confusion_matrix_finetuned.png")
print("✅ Avaliação concluída!")
