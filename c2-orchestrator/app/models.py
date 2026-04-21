# ============================================================================
# FuzzStrike C2 Orchestrator — ORM Models & Pydantic Schemas
# ============================================================================
# Defines both the SQLAlchemy ORM models (database tables) and the
# Pydantic schemas (API request/response validation) in one module.
#
# Table Design:
#   campaigns      — Tracks fuzzing campaigns (start/stop, seed, status)
#   payloads       — Stores generated mutated payloads per campaign
#   crash_reports  — Captures crash telemetry from the target environment
#   attack_metrics — Aggregated metrics for dashboard consumption
#
# Naming Convention:
#   ORM models    → PascalCase (Campaign, Payload, CrashReport)
#   Pydantic DTOs → PascalCase + suffix (CampaignCreate, CrashReportIn)
# ============================================================================

import enum
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float,
    ForeignKey, Enum as SQLEnum, LargeBinary
)
from sqlalchemy.orm import relationship

from app.database import Base


# ============================================================================
# Enums — Campaign & Payload states
# ============================================================================

class CampaignStatus(str, enum.Enum):
    """
    Lifecycle states for a fuzzing campaign.

    State transitions:
        CREATED → RUNNING → COMPLETED
                         → STOPPED (manual halt)
                         → ERROR (unrecoverable failure)
    """
    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"
    COMPLETED = "completed"
    ERROR = "error"


class PayloadStatus(str, enum.Enum):
    """
    Delivery states for an individual mutated payload.

    PENDING  → Awaiting dispatch to attack node
    SENT     → Dispatched to attack node, awaiting result
    CRASH    → This payload triggered a crash in the target
    NO_CRASH → Payload delivered, no crash detected
    ERROR    → Delivery failed (connection refused, timeout, etc.)
    """
    PENDING = "pending"
    SENT = "sent"
    CRASH = "crash"
    NO_CRASH = "no_crash"
    ERROR = "error"


# ============================================================================
# SQLAlchemy ORM Models — Database Tables
# ============================================================================

class Campaign(Base):
    """
    Represents a single fuzzing campaign.

    A campaign starts with a seed payload, generates N mutations,
    and dispatches them to attack nodes for delivery to the target.
    """
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    status = Column(
        SQLEnum(CampaignStatus),
        default=CampaignStatus.CREATED,
        nullable=False,
        index=True,
    )

    # The original seed payload (JSON string)
    seed_payload = Column(Text, nullable=False)

    # Target connection information
    target_host = Column(String(255), nullable=False, default="target")
    target_port = Column(Integer, nullable=False, default=7777)

    # Mutation configuration
    mutation_count = Column(Integer, nullable=False, default=50)

    # Aggregate counters (denormalized for dashboard performance)
    total_payloads = Column(Integer, default=0)
    payloads_sent = Column(Integer, default=0)
    payloads_crashed = Column(Integer, default=0)

    # Timestamps
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    started_at = Column(DateTime, nullable=True)
    stopped_at = Column(DateTime, nullable=True)

    # Relationships
    payloads = relationship(
        "Payload", back_populates="campaign", cascade="all, delete-orphan"
    )
    crash_reports = relationship(
        "CrashReport", back_populates="campaign", cascade="all, delete-orphan"
    )


class Payload(Base):
    """
    A single mutated payload generated from a campaign's seed.

    Each payload tracks its mutation strategy, delivery status, and
    the raw bytes that were (or will be) sent to the target.
    """
    __tablename__ = "payloads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(
        Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )

    # The mutated payload content (stored as text for JSON payloads)
    content = Column(Text, nullable=False)

    # Which mutation strategy produced this payload
    mutation_type = Column(String(100), nullable=False)

    # Size in bytes (precomputed for quick filtering)
    size_bytes = Column(Integer, nullable=False)

    # Delivery status tracking
    status = Column(
        SQLEnum(PayloadStatus),
        default=PayloadStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Timestamps
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    sent_at = Column(DateTime, nullable=True)

    # Relationship back to campaign
    campaign = relationship("Campaign", back_populates="payloads")


class CrashReport(Base):
    """
    A crash event captured by the telemetry agent when the target
    process dies or exhibits anomalous behavior.

    Contains the exact payload that triggered the crash, process
    memory stats at time of crash, and the error output.
    """
    __tablename__ = "crash_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(
        Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=True
    )

    # The payload that caused the crash (for triage reproduction)
    trigger_payload = Column(Text, nullable=True)
    trigger_payload_size = Column(Integer, nullable=True)

    # Process state at time of crash
    process_pid = Column(Integer, nullable=True)
    memory_rss_mb = Column(Float, nullable=True)  # Resident Set Size in MB
    memory_vms_mb = Column(Float, nullable=True)  # Virtual Memory Size in MB
    cpu_percent = Column(Float, nullable=True)

    # Error details
    error_type = Column(String(255), nullable=True)  # e.g., "OutOfMemoryError"
    error_message = Column(Text, nullable=True)
    stack_trace = Column(Text, nullable=True)

    # Metadata
    hostname = Column(String(255), nullable=True)
    timestamp = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Severity classification (auto-assigned by the C2 based on error type)
    severity = Column(
        String(20), default="medium", nullable=False
    )  # critical | high | medium | low

    # Relationship back to campaign
    campaign = relationship("Campaign", back_populates="crash_reports")


# ============================================================================
# Pydantic Schemas — API Request/Response Validation
# ============================================================================

# ── Campaign Schemas ──────────────────────────────────────────────────────

class SeedPayloadIn(BaseModel):
    """Schema for submitting a new seed payload."""
    content: str = Field(
        ...,
        description="The seed payload as a JSON string to be mutated",
        examples=['{"username": "admin", "password": "secret", "role": 1}'],
    )


class CampaignCreate(BaseModel):
    """Schema for creating a new fuzzing campaign."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable campaign name",
        examples=["Auth Endpoint Fuzz Run #1"],
    )
    seed_payload: str = Field(
        ...,
        description="JSON seed payload to mutate",
        examples=['{"username": "admin", "password": "secret123"}'],
    )
    target_host: str = Field(
        default="target",
        description="Target hostname or IP address",
    )
    target_port: int = Field(
        default=7777,
        ge=1,
        le=65535,
        description="Target TCP port",
    )
    mutation_count: int = Field(
        default=50,
        ge=1,
        le=10000,
        description="Number of mutated payloads to generate",
    )


class CampaignOut(BaseModel):
    """Schema for campaign responses."""
    id: int
    name: str
    status: CampaignStatus
    seed_payload: str
    target_host: str
    target_port: int
    mutation_count: int
    total_payloads: int
    payloads_sent: int
    payloads_crashed: int
    created_at: datetime
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None

    class Config:
        from_attributes = True  # Allows creation from ORM model instances


# ── Payload Schemas ───────────────────────────────────────────────────────

class PayloadOut(BaseModel):
    """Schema for payload responses."""
    id: int
    campaign_id: int
    content: str
    mutation_type: str
    size_bytes: int
    status: PayloadStatus
    created_at: datetime
    sent_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PayloadBatchOut(BaseModel):
    """Schema for a batch of payloads dispatched to attack nodes."""
    campaign_id: int
    target_host: str
    target_port: int
    payloads: list[PayloadOut]


# ── Crash Report Schemas ──────────────────────────────────────────────────

class CrashReportIn(BaseModel):
    """
    Schema for crash reports sent by the telemetry agent.

    The agent POST's this to /api/v1/telemetry/crash when it detects
    that the target process has died or become unresponsive.
    """
    campaign_id: Optional[int] = None
    trigger_payload: Optional[str] = None
    trigger_payload_size: Optional[int] = None
    process_pid: Optional[int] = None
    memory_rss_mb: Optional[float] = None
    memory_vms_mb: Optional[float] = None
    cpu_percent: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    hostname: Optional[str] = None


class CrashReportOut(BaseModel):
    """Schema for crash report responses."""
    id: int
    campaign_id: Optional[int] = None
    trigger_payload: Optional[str] = None
    trigger_payload_size: Optional[int] = None
    process_pid: Optional[int] = None
    memory_rss_mb: Optional[float] = None
    memory_vms_mb: Optional[float] = None
    cpu_percent: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    hostname: Optional[str] = None
    severity: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Metrics Schema ────────────────────────────────────────────────────────

class DashboardMetrics(BaseModel):
    """
    Aggregated metrics for the dashboard.

    Computed on-the-fly from campaign and payload tables.
    Designed for low-latency polling by the frontend.
    """
    total_campaigns: int = 0
    active_campaigns: int = 0
    total_payloads_generated: int = 0
    total_payloads_sent: int = 0
    total_crashes_detected: int = 0
    crash_rate_percent: float = 0.0
    recent_crashes: list[CrashReportOut] = []
