"""Data models shared by the AI training engine and persistence layer.

Keeping these models in a standalone module breaks the import cycle between
``core.ai_training`` (which needs the database) and ``core.database`` (which
needs the models to reconstruct training jobs).
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from pydantic import BaseModel, Field


class TrainingConfig(BaseModel):
    model_name: str
    base_model: str = "security-roberta-base-cyber"
    dataset_id: str
    task_type: str = "vulnerability_classification"  # "vulnerability_classification", "waf_anomaly_detection", "log_threat_triage"
    epochs: int = Field(default=3, ge=1, le=20)
    batch_size: int = Field(default=16, ge=1, le=128)
    learning_rate: float = Field(default=0.001, ge=0.00001, le=0.1)
    max_sequence_length: int = Field(default=256, ge=32, le=2048)
    early_stopping_patience: int = Field(default=2, ge=1, le=5)
    train_split_ratio: float = Field(default=0.8, ge=0.5, le=0.95)
    random_seed: int = 42


class TrainingJob(BaseModel):
    id: str = Field(default_factory=lambda: f"train_{uuid.uuid4().hex[:10]}")
    config: TrainingConfig
    status: str = "QUEUED"  # QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    progress_percent: int = 0
    current_epoch: int = 0
    total_epochs: int = 3
    loss_history: list[float] = Field(default_factory=list)
    accuracy_history: list[float] = Field(default_factory=list)
    val_loss_history: list[float] = Field(default_factory=list)
    val_accuracy_history: list[float] = Field(default_factory=list)
    resource_usage: dict[str, Any] = Field(default_factory=lambda: {"cpu_percent": 0.0, "memory_mb": 0.0, "device": "CPU"})
    logs: list[str] = Field(default_factory=list)
    checkpoint_path: str | None = None
    model_artifact_path: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float = 0.0
    error_message: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
