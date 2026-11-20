"""Schemas for explicitly submitted manual credential imports."""
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


class CredentialPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: Any

    @field_validator("content")
    @classmethod
    def json_document(cls, value):
        if not isinstance(value, (str, dict, list)):
            raise ValueError("A JSON document is required")
        return value


class CredentialCommitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    draft_id: str = Field(min_length=1, max_length=128)
    selected_ids: list[str] = Field(min_length=1, max_length=50)
    verify_quota: StrictBool = False

    @field_validator("selected_ids")
    @classmethod
    def bounded_ids(cls, value):
        if any(not item or len(item) > 128 for item in value):
            raise ValueError("Invalid selection")
        return value


