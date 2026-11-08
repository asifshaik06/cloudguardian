from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class Event(BaseModel):
    """Common internal event format. Every source (simulator, replay, live) must produce this."""
    event_id: str = Field(min_length=1)
    event_time: datetime
    event_source: str = Field(min_length=1)
    event_name: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    source_ip: Optional[str] = None
    aws_region: str = "us-east-1"
    error_code: Optional[str] = None
    source: str

    @field_validator("event_time")
    @classmethod
    def to_utc(cls, v):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("source")
    @classmethod
    def known_source(cls, v):
        if v not in {"simulator", "replay", "live"}:
            raise ValueError("unknown source")
        return v
