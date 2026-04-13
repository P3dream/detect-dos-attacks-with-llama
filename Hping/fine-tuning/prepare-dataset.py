# -*- coding: utf-8 -*-
import pandas as pd
import json
import random

# ───────────────────────────────────────────────
# CONFIGURAÇÃO
# ───────────────────────────────────────────────
CSV_PATH = r"C:\projects\detect-dos-attacks-with-llama\Hping\dataset\Hping.csv"
OUTPUT_PATH = "dataset_Hping.jsonl"  # JSONL de saída
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# ───────────────────────────────────────────────
# PROMPT DO SYSTEM
# ───────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are a network security analyst specialized in detecting SYN TCP flooding DDoS attacks. "
    "Analyze network flow features and respond only with a valid JSON object with the field "
    "'classification', which must be exactly 'BENIGN' or 'SYN'."
)

# ───────────────────────────────────────────────
# CARREGAR CSV
# ───────────────────────────────────────────────
df = pd.read_csv(CSV_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# RENOMEAR COLUNAS PARA PADRÃO
df = df.rename(columns={
    "Flow Packets/s": "Flow Packets per Second",
    "Avg Fwd Segment Size": "Average Forward Segment Size",
    "Fwd Segment Size Avg": "Average Forward Segment Size",
    "Init_Win_bytes_forward": "Initial Forward Window Bytes",
    "FWD Init Win Bytes": "Initial Forward Window Bytes"
})

# FILTRAR COLUNAS IMPORTANTES
required_cols = [
    "Flow Duration",
    "Flow Packets per Second",
    "Average Forward Segment Size",
    "Average Packet Size",
    "Initial Forward Window Bytes",
    "Label"
]
df = df[required_cols]

# LIMPAR NaN e inf
df = df.replace([float("inf"), float("-inf")], pd.NA)
df = df.dropna()

# PADRONIZAR LABELS
df["Label"] = "SYN"

# EMBARALHAR DATASET
df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

# ───────────────────────────────────────────────
# GERAR JSONL
# ───────────────────────────────────────────────
records = []

for _, row in df.iterrows():
    user_msg = (
        "Given this network flow data, classify the traffic as benign or SYN TCP flooding attack.\n\n"
        f"- Flow Duration: {round(float(row['Flow Duration']), 2)} µs\n"
        f"- Flow Packets per Second: {round(float(row['Flow Packets per Second']), 2)}\n"
        f"- Average Forward Segment Size: {round(float(row['Average Forward Segment Size']), 2)} bytes\n"
        f"- Average Packet Size: {round(float(row['Average Packet Size']), 2)} bytes\n"
        f"- Initial Forward Window Bytes: {round(float(row['Initial Forward Window Bytes']), 2)}\n\n"
        "Return only valid JSON with the classification field."
    )

    assistant_msg = json.dumps({"classification": row["Label"]})

    records.append({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg}
        ]
    })

# SALVAR JSONL
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"✅ JSONL gerado: {OUTPUT_PATH} → {len(records)} exemplos")
print("\n📋 Exemplo:")
print(json.dumps(records[0], indent=2, ensure_ascii=False))