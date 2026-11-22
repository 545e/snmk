"""Dataset models shared by data management and the persistence layer.

Keeping the model here avoids an import cycle between ``core.data_management``
and ``core.database``.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from pydantic import BaseModel, Field


class DatasetMetadata(BaseModel):
    id: str = Field(default_factory=lambda: f"ds_{uuid.uuid4().hex[:10]}")
    name: str
    filename: str
    file_type: str  # "csv", "jsonl", "json", "txt"
    version: str = "v1"
    record_count: int = 0
    file_size_bytes: int = 0
    fields: list[str] = Field(default_factory=list)
    target_label_field: str | None = None
    missing_values_count: int = 0
    duplicate_count: int = 0
    leakage_warnings: list[dict[str, Any]] = Field(default_factory=list)
    source: str = "Internal Security Audit"
    license: str = "Proprietary / Authorized Research"
    provenance: str = "SWA AI Security Assessment Corpus"
    permitted_use: str = "Model Training & Evaluation Only"
    train_split_count: int = 0
    val_split_count: int = 0
    test_split_count: int = 0
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
