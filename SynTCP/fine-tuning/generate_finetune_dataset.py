"""
generate_finetune_dataset.py
============================
Gera dataset de finetuning no formato ChatML (Llama 3.2) a partir do CSV balanceado.

Saída:
  - finetune_dataset.jsonl  → 80% dos dados (treino + validação no Colab)
  - test_dataset.jsonl      → 20% dos dados (teste final, nunca visto pelo modelo)
"""

import pandas as pd
import json
import random
import statistics

# ───────────────────────────────────────────────
# CONFIGURAÇÃO
# ───────────────────────────────────────────────
CSV_PATH    = r"C:\projects\detect-dos-attacks-with-llama\SynTCP\datasets\Syn_balanceado_50_50.csv"
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# ───────────────────────────────────────────────
# SYSTEM PROMPT
# ───────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are a network security analyst specialized in detecting SYN TCP flooding DDoS attacks. "
    "Analyze network flow features and respond only with a valid JSON object containing "
    "dos_attack_probability (0-100)."
)

# ───────────────────────────────────────────────
# GERADOR DE SCORE
# ───────────────────────────────────────────────
def generate_score(true_label):
    if true_label == "BENIGN":
        return 5
    else:
        return 95


# ───────────────────────────────────────────────
# TEMPLATES DE PERGUNTA
# ───────────────────────────────────────────────
USER_TEMPLATES = [
    "Analyze the following network flow and determine the probability of a SYN-based DoS attack.\n\nFlow features:\n- Flow Duration: {duration} µs\n- Flow Packets/s: {pps}\n- Avg Fwd Segment Size: {seg} bytes\n- Average Packet Size: {pkt} bytes\n- Init_Win_bytes_forward: {win} bytes\n\nRespond ONLY with JSON: {{\"dos_attack_probability\": <0-100>}}",

    "Given this network flow data, estimate the likelihood (0-100) of a SYN TCP flooding attack.\n\n- Flow Duration: {duration} µs\n- Flow Packets per Second: {pps}\n- Average Forward Segment Size: {seg} bytes\n- Average Packet Size: {pkt} bytes\n- Initial Forward Window Bytes: {win}\n\nReturn only valid JSON with dos_attack_probability.",

    "You are analyzing a captured network flow. Classify it as benign or SYN DoS attack.\n\nFeatures:\nFlow Duration={duration}, Flow Packets/s={pps}, Avg Fwd Segment Size={seg}, Average Packet Size={pkt}, Init_Win_bytes_forward={win}\n\nRespond with JSON only: {{\"dos_attack_probability\": int}}",
]

def build_user_message(row):
    template = random.choice(USER_TEMPLATES)
    return template.format(
        duration = round(float(row["Flow Duration"]), 2),
        pps      = round(float(row["Flow Packets/s"]), 2),
        seg      = round(float(row["Avg Fwd Segment Size"]), 2),
        pkt      = round(float(row["Average Packet Size"]), 2),
        win      = round(float(row["Init_Win_bytes_forward"]), 2),
    )


# ───────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────
def main():
    print("📂 Lendo CSV...")
    df = pd.read_csv(CSV_PATH, usecols=[
        "Flow Duration",
        "Flow Packets/s",
        "Avg Fwd Segment Size",
        "Average Packet Size",
        "Init_Win_bytes_forward",
        "Label"
    ], low_memory=False)

    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].astype(str).str.strip()
    df["Label"] = df["Label"].apply(lambda x: "SYN" if "syn" in x.lower() else "BENIGN")

    print(f"Total de amostras: {len(df)}")
    print(f"BENIGN: {len(df[df['Label'] == 'BENIGN'])}")
    print(f"SYN:    {len(df[df['Label'] == 'SYN'])}")

    # Embaralhar
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    # ── Gerar todos os records ──
    records = []
    errors  = 0

    for idx, row in df.iterrows():
        try:
            true_label    = row["Label"]
            prob          = generate_score(true_label)
            user_msg      = build_user_message(row)
            assistant_msg = json.dumps({"dos_attack_probability": prob})

            records.append({
                "messages": [
                    {"role": "system",    "content": SYSTEM_PROMPT},
                    {"role": "user",      "content": user_msg},
                    {"role": "assistant", "content": assistant_msg}
                ],
                "_true_label": true_label  # campo auxiliar para split estratificado
            })

        except Exception as e:
            errors += 1
            print(f"⚠️  Erro na linha {idx}: {e}")

    # ── Split 80/20 ESTRATIFICADO (garante balanço nos dois splits) ──
    benign_records = [r for r in records if r["_true_label"] == "BENIGN"]
    syn_records    = [r for r in records if r["_true_label"] == "SYN"]

    random.shuffle(benign_records)
    random.shuffle(syn_records)

    def split80(lst):
        cut = int(len(lst) * 0.8)
        return lst[:cut], lst[cut:]

    benign_train, benign_test = split80(benign_records)
    syn_train,    syn_test    = split80(syn_records)

    train_records = benign_train + syn_train
    test_records  = benign_test  + syn_test

    random.shuffle(train_records)
    random.shuffle(test_records)

    # Remover campo auxiliar antes de salvar
    for r in train_records + test_records:
        r.pop("_true_label", None)

    # ── Salvar arquivos ──
    with open("finetune_dataset.jsonl", "w", encoding="utf-8") as f:
        for r in train_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    with open("test_dataset.jsonl", "w", encoding="utf-8") as f:
        for r in test_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n✅ Datasets gerados:")
    print(f"   finetune_dataset.jsonl → {len(train_records)} exemplos (treino)")
    print(f"   test_dataset.jsonl     → {len(test_records)} exemplos (teste final)")
    print(f"   Erros ignorados:         {errors}")

    # ── Exemplo ──
    print(f"\n📋 Exemplo de entrada gerada:")
    print(json.dumps(train_records[0], indent=2, ensure_ascii=False))

    # ── Estatísticas por split ──
    for split_name, split_records in [("Treino", train_records), ("Teste", test_records)]:
        probs_benign, probs_syn = [], []
        for r in split_records:
            try:
                score = json.loads(r["messages"][2]["content"])["dos_attack_probability"]
                (probs_syn if score > 50 else probs_benign).append(score)
            except:
                pass

        print(f"\n📊 Distribuição [{split_name}]:")
        print(f"   BENIGN → {len(probs_benign)} exemplos | média score: {statistics.mean(probs_benign):.1f}")
        print(f"   SYN    → {len(probs_syn)} exemplos | média score: {statistics.mean(probs_syn):.1f}")


if __name__ == "__main__":
    main()
