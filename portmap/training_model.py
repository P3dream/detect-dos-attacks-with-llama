# =============================
# Setup Kaggle
# =============================
# Os pacotes principais já vêm instalados no Kaggle
# Atualiza pip e instala apenas se necessário
!pip install --upgrade pip
!pip install --quiet transformers datasets peft accelerate huggingface_hub

# =============================
# Imports
# =============================
import pandas as pd
import json
from datasets import Dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    DataCollatorForLanguageModeling,
    Trainer
)
from peft import LoraConfig, get_peft_model
from huggingface_hub import login
from kaggle_secrets import UserSecretsClient

# =============================
# Hugging Face login seguro
# =============================
user_secrets = UserSecretsClient()
huggingToken = user_secrets.get_secret("hugging-token")
login(token=huggingToken)

# =============================
# 1. Carregar CSV
# =============================
CSV_PATH = "/kaggle/input/portmap/Portmap.csv"
LABEL_COL = "Label"

df = pd.read_csv(CSV_PATH, low_memory=False)
df.columns = df.columns.str.strip()

# =============================
# 2. Filtrar e balancear dataset
# =============================
benign_df = df[df[LABEL_COL] == "BENIGN"]
malign_df = df[df[LABEL_COL] != "BENIGN"]

n_samples = 100
benign_df = benign_df.sample(n=n_samples, random_state=42)
malign_df = malign_df.sample(n=n_samples, random_state=42)

df_balanced = pd.concat([benign_df, malign_df]).sample(frac=1, random_state=42).reset_index(drop=True)

# =============================
# 3. Criar prompts
# =============================
def row_to_prompt(row):
    flow_json = row.to_dict()
    flow_json.pop(LABEL_COL, None)
    prompt = f"""
You are a cybersecurity agent specialized in detecting DoS attacks.
Analyze the following network flow and classify it strictly as 0 (benign) or 1 (attack).

<flow>
{json.dumps(flow_json)}
</flow>

Answer only with the number:
"""
    answer = "0" if row[LABEL_COL] == "BENIGN" else "1"
    return {"text": prompt + answer}

dataset_data = df_balanced.apply(row_to_prompt, axis=1).tolist()
ds = Dataset.from_list(dataset_data)

# =============================
# 4. Tokenização
# =============================
BASE_MODEL = "meta-llama/Llama-3.1-3B"  # modelo reduzido para Kaggle

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
tokenizer.pad_token = tokenizer.eos_token

def tokenize_function(example):
    return tokenizer(
        example["text"],
        padding="max_length",
        truncation=True,
        max_length=64  # reduz tokens para acelerar treino
    )

tokenized_ds = ds.map(tokenize_function, batched=True)
tokenized_ds = tokenized_ds.remove_columns(["text"])

train_test_split = tokenized_ds.train_test_split(test_size=0.2, seed=42)
dataset_dict = DatasetDict({
    "train": train_test_split["train"],
    "validation": train_test_split["test"]
})

# =============================
# 5. Carregar modelo base
# =============================
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    device_map="auto",   # detecta GPU
    torch_dtype="auto"   # usa FP16 na GPU
)

# =============================
# 6. Configurar LoRA
# =============================
lora_config = LoraConfig(
    r=16,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

model = get_peft_model(model, lora_config)

# =============================
# 7. Treinamento
# =============================
training_args = TrainingArguments(
    output_dir="./lora-dos-detector",
    per_device_train_batch_size=1,
    gradient_accumulation_steps=16,
    warmup_steps=50,
    max_steps=500,  # suficiente para validação rápida
    learning_rate=2e-4,
    fp16=True,
    logging_steps=10,
    save_strategy="steps",
    save_steps=200,
    eval_steps=100,
    remove_unused_columns=False
)

data_collator = DataCollatorForLanguageModeling(tokenizer, mlm=False, pad_to_multiple_of=8)

trainer = Trainer(
    model=model,
    train_dataset=dataset_dict["train"],
    eval_dataset=dataset_dict["validation"],
    args=training_args,
    data_collator=data_collator
)

print("🚀 Iniciando treino LoRA...")
trainer.train()
print("✅ Treino finalizado!")

# =============================
# 8. Salvar adaptadores LoRA
# =============================
model.save_pretrained("./lora-dos-detector")
tokenizer.save_pretrained("./lora-dos-detector")
print("📁 Modelo LoRA salvo em ./lora-dos-detector")
