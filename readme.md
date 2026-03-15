# GenGuardian

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![LLaMA](https://img.shields.io/badge/Model-LLaMA%203.2-orange)
![Research](https://img.shields.io/badge/Type-Academic%20Research-green)
![License](https://img.shields.io/badge/License-LLaMA%20Community-red)

**GenGuardian** is an AI-powered intrusion detection and prevention system that uses a fine-tuned Large Language Model (LLM) to detect Distributed Denial of Service (DDoS) attacks in real time.

This repository contains the implementation developed as part of the research:

> *"GenGuardian: DDoS Detection Using LLaMA Models with Fine-Tuning and Quantization"*  
> Bachelor's Thesis — CEFET/RJ, 2026

---

## Overview

Traditional intrusion detection systems rely on statistical analysis or classical machine learning approaches. **GenGuardian** takes a different path: it leverages a **fine-tuned LLaMA model** to analyze structured network flow data and classify traffic as benign or malicious.

The system is designed to be **lightweight and deployable**, capable of running even in environments with limited computational resources thanks to **4-bit quantization via QLoRA**.

---

## Key Features

- DDoS detection using a **fine-tuned LLaMA 3.2 (1B)** model
- Lightweight inference via **4-bit quantization (QLoRA)**
- Real-time network traffic analysis
- Integration with standard packet capture tools (**TShark**)
- Automatic mitigation through firewall rules (**iptables**)
- Designed for research in **AI-driven cybersecurity**

---

## System Architecture

<p align="center">
  <img src="docs/architecture.png" width="850">
</p>

### Processing Pipeline

**Client → Server → Traffic Capture → GenGuardian Controller → Analysis → Mitigation**

1. A client sends traffic to the server
2. The server captures network flow data
3. The GenGuardian controller extracts and processes traffic features
4. The LLM classifies each flow as **benign or malicious**
5. If an attack is detected, mitigation actions are triggered (e.g., IP blocking)

---

## Experimental Environment

<p align="center">
  <img src="docs/environment.png" width="850">
</p>

The experiments were conducted in a **controlled virtualized environment** designed to simulate DDoS attacks.

### Infrastructure

| Component | Description |
|---|---|
| Ubuntu Server VM | Target system hosting the monitored service |
| Ubuntu Attacker VM | Generates attack traffic (e.g., using `hping3`) |
| Host Machine | Runs the GenGuardian controller and LLaMA inference pipeline |

All machines communicate through an **isolated host-only virtual network**, ensuring that experiments remain contained and reproducible.

---

## Model

| Property | Value |
|---|---|
| Base model | LLaMA 3.2 — 1B parameters |
| Training method | Supervised Fine-Tuning (SFT) |
| Optimization | QLoRA (Quantized Low-Rank Adaptation) |
| Quantization | 4-bit |

This configuration enables **local execution with low hardware requirements** while maintaining strong detection performance.

---

## Pre-trained Models

The fine-tuned models are available on Hugging Face in **GGUF format** for local inference with tools like `llama.cpp` or `Ollama`.

| Model | Description | Quantization | Link |
|---|---|---|---|
| genguardian-syn-1b | SYN Flood detection | Q4_K_M | [🤗 Hugging Face](https://huggingface.co/P3dream/genguardian-syn-flood-detector) |
| genguardian-udplag-1b | UDPLag detection | Q4_K_M | [🤗 Hugging Face](https://huggingface.co/P3dream/genguardian-udp-lag-detector) |
| genguardian-multiclass-1b | Multiclass detection (BENIGN / SYN / UDPLag / UDP) | Q4_K_M | [🤗 Hugging Face](https://huggingface.co/P3dream/genguardian-multiclass-detector) |

### Running with Ollama

```bash
# SYN Flood model
ollama run p3dream/genguardian-syn-1b

# UDPLag model
ollama run p3dream/genguardian-udplag-1b

# Multiclass model
ollama run p3dream/genguardian-multiclass-1b
```

### Running with llama.cpp

```bash
./llama-cli -m genguardian-syn-1b.Q4_K_M.gguf \
  -p "Flow Duration=102.0, Flow Packets/s=39215.69, Avg Fwd Segment Size=6.0, Average Packet Size=7.5, Init_Win_bytes_forward=5840.0"
```

---

## Dataset

Training and evaluation were performed using the **CICDDoS2019 dataset** published by the Canadian Institute for Cybersecurity.

https://www.unb.ca/cic/datasets/ddos-2019.html

---

### Selected Features

Different feature sets were used depending on the **attack scenario evaluated**.

#### SYN Flood Detection

The following flow features were selected based on their relevance for SYN Flood behavior:

- Flow Duration
- Flow Packets/s
- Avg Fwd Segment Size
- Average Packet Size
- Init_Win_bytes_forward

These features capture characteristics such as **packet rate, packet size, and connection behavior**, which are commonly associated with SYN Flood attacks.

---

#### UDPLag / Multiclass Detection

For **UDPLag and multiclass experiments**, a different subset of flow features was used:

- Min Packet Length
- Avg Fwd Segment Size
- Flow Bytes/s
- URG Flag Count
- Fwd Packets/s

These features were chosen to capture **traffic burst patterns and abnormal packet rates**, which are typical of UDP-based flooding attacks.

---

### Dataset Preparation

The dataset was converted into a **ChatML conversational format** to enable supervised fine-tuning of the LLaMA model.

Example training sample:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are a network security analyst specialized in detecting UDPLag DDoS attacks."
    },
    {
      "role": "user",
      "content": "Min Packet Length=442.0, Avg Fwd Segment Size=442.0, Flow Bytes/s=294666666.67, URG Flag Count=0.0, Fwd Packets/s=666666.67"
    },
    {
      "role": "assistant",
      "content": "{\"classification\": \"UDPLag\"}"
    }
  ]
}
```

To reduce dataset imbalance, **undersampling** was applied to the majority class.

---

## Experiments

Three experimental scenarios were evaluated:

| Scenario | Description |
|---|---|
| 1 | Zero-shot LLM classification |
| 2 | Prompt engineering |
| 3 | Fine-tuned model |

The fine-tuned model significantly outperformed the base model, achieving **detection accuracy above 98%** in several scenarios.

---

## Tech Stack

- **Python** — Core pipeline and data processing
- **FastAPI** — Controller API
- **PyTorch + Transformers** — Model training and inference
- **QLoRA / PEFT** — Efficient fine-tuning
- **TShark** — Network traffic capture
- **iptables** — Firewall-based mitigation

---

## Example Workflow

1. Capture network traffic with TShark
2. Extract flow features from captured packets
3. Convert structured data into prompt format
4. Query the fine-tuned LLaMA model
5. Parse the classification result (benign / malicious)
6. Apply mitigation rules if an attack is detected

---

## Research Context

This project was developed as a **Bachelor's Thesis in Computer Engineering** at:

**CEFET/RJ — Centro Federal de Educação Tecnológica Celso Suckow da Fonseca**

| Role | Name |
|---|---|
| Author | Pedro Carneiro Pizzi |
| Advisor | Prof. Dalbert Matos Mascarenhas |

---

## Future Work

- Real-time deployment in production environments
- Integration with **Software Defined Networking (SDN)** controllers
- Detection of additional DDoS attack types
- Training on larger multi-class datasets
- Adaptive automated response policies

---

## Licenses & Attribution

### Dataset

The CICDDoS2019 dataset is published by the Canadian Institute for Cybersecurity:

https://www.unb.ca/cic/datasets/ddos-2019.html

### Model

This project uses models from the **LLaMA family developed by Meta**, distributed under the **LLaMA Community License Agreement**:

https://ai.meta.com/llama/license

---

## Citation

```bibtex
@thesis{pizzi2026genguardian,
  author  = {Pedro Carneiro Pizzi},
  title   = {GenGuardian: DDoS Detection Using LLaMA Models with Fine-Tuning and Quantization},
  school  = {CEFET/RJ},
  year    = {2026},
  type    = {Bachelor's Thesis}
}
```

---

## Contact

**Pedro Carneiro Pizzi**

- https://www.pedropizzi.com
- https://linkedin.com/in/pedrocarneiropizzi
- https://github.com/p3dream