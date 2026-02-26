#!/usr/bin/env python3
"""
evaluate_detector.py

Avalia a performance do detector lendo arquivos JSONL com registros.
- Usa threshold = 60% (>=60 => predição 'ataque')
- Calcula TP, TN, FP, FN, acurácia, precisão, recall, F1
- Gera relatório JSON e CSV.

Usage:
    python3 evaluate_detector.py                # lê arquivos padrão
    python3 evaluate_detector.py file1.jsonl ...  # lê arquivos passados por argumento

Saída:
    metrics_report.json
    metrics_report.csv
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import csv

# Threshold (em porcentagem)
THRESHOLD = 75.0

# Arquivos padrão se nenhum argumento for passado
DEFAULT_FILES = ["resultados_teste.jsonl", "resultados_normal_only.jsonl"]

def load_jsonl(path):
    recs = []
    p = Path(path)
    if not p.exists():
        print(f"[warn] arquivo não encontrado: {path}")
        return recs
    with p.open("r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
                recs.append(rec)
            except json.JSONDecodeError:
                # tenta recuperar removendo vírgula final (caso o JSONL tenha sido salvo com vírgulas)
                try:
                    rec = json.loads(ln.rstrip(","))
                    recs.append(rec)
                except Exception as e:
                    print(f"[erro] falha ao parsear linha em {path}: {e}")
    return recs

def extract_prob(rec):
    """Tenta extrair um número de 'dos_attack_probability' do registro.
       Retorna None se não encontrado ou inválido."""
    dr = rec.get("detector_result") or {}
    # dr pode ser dict com 'dos_attack_probability' ou 'error' + 'raw'
    if isinstance(dr, dict) and "dos_attack_probability" in dr:
        v = dr["dos_attack_probability"]
        try:
            return float(v)
        except Exception:
            try:
                s = str(v).strip().rstrip("%")
                return float(s)
            except Exception:
                return None
    # se não, tenta analisar 'raw' se existir (texto JSON bruto)
    if isinstance(dr, dict) and dr.get("raw"):
        raw = dr.get("raw")
        try:
            parsed = json.loads(raw)
            if "dos_attack_probability" in parsed:
                return float(parsed["dos_attack_probability"])
        except Exception:
            pass
    return None

def label_pred_from_prob(prob, threshold=THRESHOLD):
    if prob is None:
        return "unknown"
    return "ataque" if prob >= threshold else "normal"

def evaluate(records):
    stats = {
        "total": 0,
        "by_label": Counter(),
        "by_pred": Counter(),
        "tp": 0, "tn": 0, "fp": 0, "fn": 0,
    }
    per_scenario = defaultdict(lambda: {"count":0, "tp":0, "tn":0, "fp":0, "fn":0})
    rows = []  # para csv de saída detalhado

    for rec in records:
        stats["total"] += 1
        label = rec.get("label_real")
        if label not in ("ataque","normal"):
            # se label estiver faltando, tenta procurar em 'cenario' (não ideal)
            label = rec.get("label_real", "unknown")
        stats["by_label"][label] += 1

        prob = extract_prob(rec)
        pred = label_pred_from_prob(prob)
        stats["by_pred"][pred] += 1

        # considerar apenas registros com label real válido para métricas
        if label in ("ataque","normal") and pred in ("ataque","normal"):
            if label == "ataque" and pred == "ataque":
                stats["tp"] += 1
                per_scenario[rec.get("cenario", "unknown")]["tp"] += 1
            elif label == "normal" and pred == "normal":
                stats["tn"] += 1
                per_scenario[rec.get("cenario", "unknown")]["tn"] += 1
            elif label == "normal" and pred == "ataque":
                stats["fp"] += 1
                per_scenario[rec.get("cenario", "unknown")]["fp"] += 1
            elif label == "ataque" and pred == "normal":
                stats["fn"] += 1
                per_scenario[rec.get("cenario", "unknown")]["fn"] += 1
            per_scenario[rec.get("cenario", "unknown")]["count"] += 1

        # detalhe para csv
        rows.append({
            "timestamp_start": rec.get("timestamp_start"),
            "cenario": rec.get("cenario"),
            "label_real": label,
            "predicao": pred,
            "probability": extract_prob(rec),
            "watchdog_reason": rec.get("watchdog_reason"),
            "ia_wait_secs": rec.get("ia_wait_secs"),
        })

    # métricas
    tp = stats["tp"]; tn = stats["tn"]; fp = stats["fp"]; fn = stats["fn"]
    total_valid = tp + tn + fp + fn
    accuracy = (tp + tn) / total_valid if total_valid else None
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall and (precision+recall)>0) else None

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "threshold": THRESHOLD,
        "total_records": stats["total"],
        "label_counts": dict(stats["by_label"]),
        "prediction_counts": dict(stats["by_pred"]),
        "total_valid_for_metrics": total_valid,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_scenario": {},
    }

    # per-scenario formatting
    for scen, vals in per_scenario.items():
        c = vals.get("count",0)
        tp_s = vals.get("tp",0); tn_s = vals.get("tn",0); fp_s = vals.get("fp",0); fn_s = vals.get("fn",0)
        prec = tp_s / (tp_s + fp_s) if (tp_s + fp_s) else None
        rec = tp_s / (tp_s + fn_s) if (tp_s + fn_s) else None
        f1_s = (2*prec*rec/(prec+rec)) if (prec and rec and (prec+rec)>0) else None
        report["per_scenario"][scen] = {
            "count": c, "TP": tp_s, "TN": tn_s, "FP": fp_s, "FN": fn_s,
            "precision": prec, "recall": rec, "f1": f1_s
        }

    return report, rows

def save_report(report, rows, out_json="metrics_report.json", out_csv="metrics_report.csv"):
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    # grava CSV detalhado
    fieldnames = ["timestamp_start","cenario","label_real","predicao","probability","watchdog_reason","ia_wait_secs"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k) for k in fieldnames})

def main():
    files = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_FILES
    all_recs = []
    for fn in files:
        recs = load_jsonl(fn)
        print(f"[info] carregados {len(recs)} registros de {fn}")
        all_recs.extend(recs)
    if not all_recs:
        print("Nenhum registro encontrado. Saindo.")
        return

    report, rows = evaluate(all_recs)
    save_report(report, rows)
    # imprime resumo
    print("\n==== Relatório resumo ====")
    print(f"Registros totais lidos: {report['total_records']}")
    print(f"Registros válidos para métricas: {report['total_valid_for_metrics']}")
    print(f"TP: {report['TP']}, TN: {report['TN']}, FP: {report['FP']}, FN: {report['FN']}")
    print(f"Acurácia: {report['accuracy']}")
    print(f"Precisão: {report['precision']}")
    print(f"Recall: {report['recall']}")
    print(f"F1: {report['f1']}")
    print("Relatório completo salvo em metrics_report.json e metrics_report.csv")

if __name__ == "__main__":
    main()
