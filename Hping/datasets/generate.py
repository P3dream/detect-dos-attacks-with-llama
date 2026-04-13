import json
import random

random.seed(42)

def load_jsonl(path):
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            data.append(json.loads(line))
    return data

# 🔹 Carrega datasets
syn_data = load_jsonl("test_dataset.jsonl")   # só SYN
benign_data = load_jsonl("legit.jsonl")       # só BENIGN

print(f"SYN total: {len(syn_data)}")
print(f"BENIGN total: {len(benign_data)}")

# 🔹 Amostragem
syn_sample = random.sample(syn_data, 50)
benign_sample = random.sample(benign_data, 50)

# 🔹 Junta + embaralha
final_data = syn_sample + benign_sample
random.shuffle(final_data)

print(f"\nDataset final: {len(final_data)} amostras")

# 🔹 Salva
with open("mixed_50_50.jsonl", "w", encoding="utf-8") as f:
    for item in final_data:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print("✅ mixed_50_50.jsonl gerado")