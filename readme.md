# GenGuardian

**GenGuardian** is an AI-powered intrusion detection and prevention system that uses a fine-tuned Large Language Model (LLM) to detect Distributed Denial of Service (DDoS) attacks in real time.

This repository contains the implementation developed as part of the research:

> *"GenGuardian: DDoS Detection Using LLaMA Models with Fine-Tuning and Quantization"*
> Bachelor's Thesis — CEFET/RJ, 2026

---

## Overview

Traditional intrusion detection systems rely on statistical analysis or classical machine learning approaches. GenGuardian takes a different path: it leverages a **fine-tuned LLaMA model** to analyze structured network flow data and classify traffic as benign or malicious.

The system is designed to be **lightweight and deployable**, capable of running even in environments with limited computational resources, thanks to 4-bit quantization via QLoRA.

---

## Key Features

- DDoS detection using a **fine-tuned LLaMA 3.2 (1B)** model
- Lightweight inference via **4-bit quantization (QLoRA)**
- Real-time network traffic analysis
- Integration with standard packet capture tools (TShark)
- Automatic mitigation through firewall rules (iptables)
- Designed for research in **AI-driven cybersecurity**

---

## System Architecture

```
Client → Server → Traffic Capture → GenGuardian Controller → Analysis → Mitigation
```

1. A client sends traffic to the server
2. The server captures network flow data
3. The GenGuardian controller extracts and processes traffic features
4. The LLM classifies each flow as benign or malicious
5. If an attack is detected, mitigation actions are triggered (e.g., IP blocking)

---

## Model

| Property | Value |
|---|---|
| Base model | LLaMA 3.2 – 1B parameters |
| Training method | Supervised Fine-Tuning (SFT) |
| Optimization | QLoRA (Quantized Low-Rank Adaptation) |
| Quantization | 4-bit |

This configuration enables local execution while maintaining strong detection performance.

---

## Dataset

Training and evaluation were performed using the [CICDDoS2019 Dataset](https://www.unb.ca/cic/datasets/ddos-2019.html) from the Canadian Institute for Cybersecurity.

**Selected features:**

- Flow Duration
- Flow Packets/s
- Avg Fwd Segment Size
- Average Packet Size
- Init_Win_bytes_forward

The dataset was balanced using **undersampling** to prevent bias toward the majority class.

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

```
1. Capture network traffic with TShark
2. Extract flow features from captured packets
3. Convert structured data into prompt format
4. Query the fine-tuned LLaMA model
5. Parse the classification result (benign / malicious)
6. Apply mitigation rules if an attack is detected
```

---

## Research Context

This project was developed as a Bachelor's Thesis in Computer Engineering at:

**CEFET/RJ** — Centro Federal de Educação Tecnológica Celso Suckow da Fonseca

| Role | Name |
|---|---|
| Author | Pedro Carneiro Pizzi |
| Advisor | Prof. Dalbert Matos Mascarenhas |

---

## Future Work

- Real-time deployment in production environments
- Integration with SDN controllers
- Detection of additional DDoS attack types
- Training on larger, multi-class datasets
- Automated and adaptive response policies

---

## Licenses & Attribution

### Dataset

The CICDDoS2019 dataset is published by the Canadian Institute for Cybersecurity:
https://www.unb.ca/cic/datasets/ddos-2019.html

### Model

This project uses models from the LLaMA family developed by Meta, distributed under the **LLaMA Community License Agreement**:
https://ai.meta.com/llama/license

---

## Citation

If you use this project in academic research, please cite:

```
Pizzi, Pedro.
GenGuardian: DDoS Detection Using LLaMA Models with Fine-Tuning and Quantization.
Bachelor's Thesis – CEFET/RJ, 2026.
```

---

## Contact

**Pedro Carneiro Pizzi**

- [Website](https://www.pedropizzi.com)
- [LinkedIn](https://linkedin.com/in/pedrocarneiropizzi)
- [GitHub](https://github.com/p3dream)
