# SWA AI — Model Training, Fine-Tuning & Evaluation Guide

> **Correction applied 2026-11-11 (read first or stop here):** there is NO real ML training anywhere in this repository.
> - `/api/ai/training/start` runs `core/ai_training.py`, an explicit **simulation**: the "loss" is `2.45 * e^-0.45·epoch + hash-noise`, accuracy is capped at 0.985, `time.sleep(1)` per epoch, and the "model" artifact (`swa_security_model.bin`) is a text file of metadata. No `torch`/`transformers`/`sklearn` is installed; no weights are computed; no GPU is used.
> - No credential-leakage scanning of uploaded datasets exists as described below (dataset upload does have basic handling, but the leakage scanner is not ML-grade; treat this section as aspirational unless re-verified).
> - `security-roberta-base` / `payload-anomaly-detector` / `cyber-distilbert-uncased` do not exist in this repo, and nothing downloads them.
> - "Zero Data Leakage", "Reproducible 70/15/15 partitioning", and "epoch checkpointing" describe the simulation's bookkeeping, not real training dynamics.
> - Model evaluation (`ai_evaluation.py`) is real code but evaluates a **regex signature classifier** against labeled data, plus latency timing of live LLM calls when a key is configured. There is no trained model under test.
> - The honest capability matrix is in `docs/COMPLETE_AI_SYSTEM_INVENTORY.md`.
>
> The rest of this document describes the intended end-state design, kept for reference. It is NOT a description of working functionality.

## 1. Overview & Architectural Capabilities
The SWA AI training and evaluation engine is built specifically for cybersecurity teams to develop, fine-tune, evaluate, and benchmark bespoke security classifiers, payload anomaly detectors, and LLM reasoning models.

Unlike generic machine learning harnesses, SWA AI enforces:
- **Zero Data Leakage:** Automatic secret detection (AWS keys, private certificates, JWT tokens, connection strings) on uploaded corpora prior to training.
- **Hardware Auto-Detection:** Automatically detects CUDA GPUs, Apple Silicon MPS Neural Engines, or multicore CPUs and sets memory/batch size bounds accordingly.
- **Reproducible Partitioning:** Deterministic train/validation/test splits (70/15/15) with random seeds.
- **Epoch Loss Tracking & Checkpointing:** Real-time loss decay recording, validation accuracy evaluation, and persistent `.json` and binary model weights artifacts saved to `data/model_checkpoints/`.

---

## 2. Supported Model Types & Architectures

| Archetype | Task Description | Default Base Architecture | Supported Hardware |
| :--- | :--- | :--- | :--- |
| `vulnerability_classification` | Multi-class categorization of malicious payloads (SQLi, XSS, SSRF, RCE, IDOR) | `security-roberta-base` | CUDA, MPS, CPU |
| `waf_anomaly_detection` | Real-time classification of abnormal HTTP request parameters and path anomalies | `payload-anomaly-detector` | CUDA, CPU |
| `log_threat_triage` | Triaging Suricata IDS alerts, Apache/Nginx weblogs, and SSH authentication events | `cyber-distilbert-uncased` | CUDA, MPS, CPU |

---

## 3. Dataset Requirements & Schema

Datasets must be uploaded through the **Data Management** panel (`/api/datasets/upload`) in one of the supported formats:
- **CSV:** Headers such as `payload,category,label,description`.
- **JSONL:** One JSON dictionary per line with `{"text": "...", "label": "..."}`.
- **JSON:** Array of JSON objects.
- **TXT:** Raw sample lines.

### Automated Leakage Detection
Uploaded datasets are scanned against credential patterns:
- AWS Access Keys (`AKIA...`)
- Private RSA/EC keys
- Bearer tokens and API keys
- JSON Web Tokens (JWT)
- Database credentials (`postgres://...`)

---

## 4. Training Workflow & Hyperparameters

### API Endpoint: `POST /api/ai/training/start`

```json
{
  "model_name": "swa-vuln-classifier-prod",
  "base_model": "security-roberta-base",
  "dataset_id": "ds_a1b2c3d4e5",
  "task_type": "vulnerability_classification",
  "epochs": 3,
  "batch_size": 16,
  "learning_rate": 0.001,
  "max_sequence_length": 256,
  "train_split_ratio": 0.8
}
```

### Checkpoints and Artifacts
Every epoch produces a snapshot in `data/model_checkpoints/{job_id}/`:
- `checkpoint_epoch_{n}.json`: Loss, validation loss, accuracy, and timestamp.
- `swa_security_model.bin`: Final serialized weights and metadata.

---

## 5. Model Evaluation & Benchmarking

### API Endpoint: `POST /api/ai/evaluation/run`

```json
{
  "model_name": "swa-vuln-classifier-prod",
  "baseline_model_name": "heuristic-baseline-v1",
  "task_type": "classification",
  "test_sample_count": 150
}
```

### Metrics Calculated:
1. **Precision:** $\frac{TP}{TP + FP}$
2. **Recall:** $\frac{TP}{TP + FN}$
3. **F1-Score:** $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
4. **Accuracy:** $\frac{TP + TN}{\text{Total Samples}}$
5. **2x2 Confusion Matrix:** True Positives, False Positives, True Negatives, False Negatives.
6. **Inference Latency:** Average milliseconds per inference query.
7. **Throughput:** Processed tokens / requests per second.
8. **Estimated Provider Cost:** Calculated against official provider pricing tiers ($/1M tokens).
