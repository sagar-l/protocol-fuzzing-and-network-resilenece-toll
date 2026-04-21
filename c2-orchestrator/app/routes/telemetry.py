# ============================================================================
# FuzzStrike C2 Orchestrator — Crash Telemetry Routes
# ============================================================================
# Endpoints for ingesting crash telemetry from the Docker agent.
# The agent POSTs crash reports here when it detects that the target
# process has died or exhibited anomalous behavior.
#
# Route Map:
#   POST /api/v1/telemetry/crash     → Ingest a crash report
#   GET  /api/v1/telemetry/crashes   → List crash reports
#   GET  /api/v1/telemetry/crashes/{id} → Get a specific crash report
# ============================================================================

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from loguru import logger

from app.database import get_db
from app.models import (
    CrashReport, CrashReportIn, CrashReportOut,
    Campaign, CampaignStatus,
)

router = APIRouter(prefix="/api/v1/telemetry", tags=["Telemetry"])


def _classify_severity(error_type: Optional[str], memory_rss_mb: Optional[float]) -> str:
    """
    Auto-classify crash severity based on error type and memory stats.

    Severity levels:
        critical — Memory exhaustion, OOM kills (exploitable DoS)
        high     — Unhandled exceptions, segfaults (potential RCE)
        medium   — Application-level errors (logic bugs)
        low      — Timeouts, connection resets (minor issues)

    Args:
        error_type: The type of error reported by the agent.
        memory_rss_mb: Resident set size at time of crash.

    Returns:
        str: Severity classification string.
    """
    if not error_type:
        return "medium"

    error_lower = error_type.lower()

    # Critical: Memory-related crashes
    if any(keyword in error_lower for keyword in [
        "outofmemory", "oom", "memory", "killed", "sigkill"
    ]):
        return "critical"

    # Critical: High memory usage at crash time
    if memory_rss_mb and memory_rss_mb > 500:
        return "critical"

    # High: Segfaults, access violations, stack overflows
    if any(keyword in error_lower for keyword in [
        "segfault", "sigsegv", "stackoverflow", "accessviolation",
        "bufferoverflow", "heapcorruption"
    ]):
        return "high"

    # Low: Timeouts and connection issues
    if any(keyword in error_lower for keyword in [
        "timeout", "connectionreset", "connectionrefused", "eof"
    ]):
        return "low"

    # Default: Medium severity
    return "medium"


# ============================================================================
# POST /api/v1/telemetry/crash — Ingest a crash report
# ============================================================================
@router.post("/crash", response_model=CrashReportOut, status_code=201)
def report_crash(
    report_in: CrashReportIn,
    db: Session = Depends(get_db),
):
    """
    Ingest a crash report from the telemetry agent.

    This is called by agent.py when it detects that the target process
    has crashed. The report includes:
    - The payload that triggered the crash
    - Process memory/CPU stats at time of crash
    - Error type and stack trace

    The crash is automatically classified by severity and linked to
    the active campaign (if one exists).
    """
    logger.warning(
        f"🔥 CRASH REPORT RECEIVED | "
        f"Error: {report_in.error_type} | "
        f"Memory: {report_in.memory_rss_mb} MB | "
        f"Payload Size: {report_in.trigger_payload_size} bytes"
    )

    # Auto-classify severity
    severity = _classify_severity(report_in.error_type, report_in.memory_rss_mb)

    # If no campaign_id provided, try to find the active campaign
    campaign_id = report_in.campaign_id
    if not campaign_id:
        active_campaign = (
            db.query(Campaign)
            .filter(Campaign.status == CampaignStatus.RUNNING)
            .order_by(Campaign.started_at.desc())
            .first()
        )
        if active_campaign:
            campaign_id = active_campaign.id

    # Create the crash report record
    crash_report = CrashReport(
        campaign_id=campaign_id,
        trigger_payload=report_in.trigger_payload,
        trigger_payload_size=report_in.trigger_payload_size,
        process_pid=report_in.process_pid,
        memory_rss_mb=report_in.memory_rss_mb,
        memory_vms_mb=report_in.memory_vms_mb,
        cpu_percent=report_in.cpu_percent,
        error_type=report_in.error_type,
        error_message=report_in.error_message,
        stack_trace=report_in.stack_trace,
        hostname=report_in.hostname,
        severity=severity,
    )

    db.add(crash_report)

    # Update campaign crash counter if linked
    if campaign_id:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            campaign.payloads_crashed += 1

    db.commit()
    db.refresh(crash_report)

    logger.warning(
        f"🔥 Crash #{crash_report.id} saved | "
        f"Severity: {severity.upper()} | "
        f"Campaign: {campaign_id or 'unlinked'}"
    )

    return crash_report


# ============================================================================
# GET /api/v1/telemetry/crashes — List crash reports
# ============================================================================
@router.get("/crashes", response_model=list[CrashReportOut])
def list_crashes(
    campaign_id: Optional[int] = Query(None, description="Filter by campaign"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    List crash reports with optional filtering by campaign and severity.
    Results are ordered by timestamp (newest first).
    """
    query = db.query(CrashReport)

    if campaign_id:
        query = query.filter(CrashReport.campaign_id == campaign_id)
    if severity:
        query = query.filter(CrashReport.severity == severity)

    crashes = (
        query
        .order_by(CrashReport.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return crashes


# ============================================================================
# GET /api/v1/telemetry/crashes/{id} — Get a specific crash report
# ============================================================================
@router.get("/crashes/{crash_id}", response_model=CrashReportOut)
def get_crash(
    crash_id: int,
    db: Session = Depends(get_db),
):
    """Get detailed information about a specific crash report."""
    crash = db.query(CrashReport).filter(CrashReport.id == crash_id).first()

    if not crash:
        raise HTTPException(status_code=404, detail=f"Crash report {crash_id} not found")

    return crash
