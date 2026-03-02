import json
import requests
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report
import matplotlib.pyplot as plt
import os

TEST_DATASET_PATH = r"C:\projects\detect-dos-attacks-with-llama\Multiclasses\datasets\test_dataset_multiclass.jsonl"
LOG_PATH          = r"C:\projects\detect-dos-attacks-with-llama\logs\multiclass_test_log_finetuned.json"
API_URL           = "http://localhost:3000/ia"

VALID_LABELS = ["BENIGN", "UDPLag", "UDP", "Syn"]

print("🔍 Lendo test_dataset_multiclass.jsonl...")

records = []
with open(TEST_DATASET_PATH, encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))

print(f"✅ Total de exemplos: {len(records)}")

records = records[:100]

y_true = []
y_pred = []
log_entries = []
errors = 0

total         = len(records)
progress_step = max(total // 10, 1)

print(f"🚀 Enviando {total} fluxos para o modelo...\n")

for idx, r in enumerate(records):
    true_label   = json.loads(r["messages"][2]["content"])["classification"]
    user_content = r["messages"][1]["content"]

    try:
        response  = requests.post(API_URL, json=[user_content], timeout=120)
        result    = response.json()
        predicted = result.get("result", {}).get("classification", "BENIGN")

        if predicted not in VALID_LABELS:
            predicted = "BENIGN"

    except Exception as e:
        print(f"⚠️ Erro no fluxo {idx}: {e}")
        predicted = "BENIGN"
        result    = {"error": str(e)}
        errors   += 1

    y_true.append(true_label)
    y_pred.append(predicted)

    log_entries.append({
        "flow_id":      idx,
        "true_label":   true_label,
        "predicted":    predicted,
        "raw_response": result
    })

    if (idx + 1) % progress_step == 0 or (idx + 1) == total:
        pct = int((idx + 1) / total * 100)
        print(f"📤 Progresso: {idx + 1}/{total} ({pct}%)")

# --- Salvar logs ---
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
with open(LOG_PATH, "w", encoding="utf-8") as f:
    json.dump(log_entries, f, indent=4, ensure_ascii=False)

print(f"\n📁 Logs salvos em {LOG_PATH}")
print(f"⚠️  Erros de requisição: {errors}")

# --- Resultados ---
print(f"\n📊 Resultado final:")
print(classification_report(y_true, y_pred, labels=VALID_LABELS, digits=4))

# --- Matriz de Confusão ---
cm   = confusion_matrix(y_true, y_pred, labels=VALID_LABELS)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=VALID_LABELS)

plt.figure(figsize=(7, 7))
disp.plot(values_format='d')
plt.title("Matriz de Confusão — Llama 3.2-1B Finetuned vs Multiclass Dataset")
plt.savefig("confusion_matrix_multiclass_finetuned.png", dpi=150)
plt.close()

print("📊 Matriz salva como confusion_matrix_multiclass_finetuned.png")
print("✅ Avaliação concluída!")