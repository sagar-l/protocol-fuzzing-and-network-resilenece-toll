# ============================================================================
# FuzzStrike C2 Orchestrator — Campaign Management Routes
# ============================================================================
# Endpoints for creating, starting, stopping, and querying fuzzing campaigns.
#
# Route Map:
#   POST   /api/v1/campaigns/          → Create a new campaign + generate payloads
#   GET    /api/v1/campaigns/          → List all campaigns
#   GET    /api/v1/campaigns/{id}      → Get campaign details
#   POST   /api/v1/campaigns/{id}/start → Start a campaign (mark as RUNNING)
#   POST   /api/v1/campaigns/{id}/stop  → Stop a campaign (mark as STOPPED)
#   GET    /api/v1/campaigns/{id}/payloads → Get pending payloads for dispatch
#   POST   /api/v1/campaigns/{id}/payloads/ack → Acknowledge payload delivery
# ============================================================================

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from loguru import logger

from app.database import get_db
from app.models import (
    Campaign, CampaignCreate, CampaignOut, CampaignStatus,
    Payload, PayloadOut, PayloadBatchOut, PayloadStatus,
    DashboardMetrics, CrashReport, CrashReportOut,
    FuzzProtocol, FuzzDirection,
)
from app.mutator import mutate_seed

router = APIRouter(prefix="/api/v1/campaigns", tags=["Campaigns"])


# ============================================================================
# POST /api/v1/campaigns/ — Create a new campaign
# ============================================================================
@router.post("/", response_model=CampaignOut, status_code=201)
def create_campaign(
    campaign_in: CampaignCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new fuzzing campaign.

    This endpoint:
    1. Creates the campaign record in the database.
    2. Runs the mutation engine to generate mutated payloads from the seed.
    3. Stores payloads in batches of 10,000 for memory efficiency at scale.

    Supports up to 10 million payloads for high-volume protocol fuzzing.
    """
    logger.info(f"Creating campaign: {campaign_in.name} "
                f"(protocol={campaign_in.protocol}, count={campaign_in.mutation_count:,})")

    # ── Step 1: Create the campaign record ─────────────────────────────
    campaign = Campaign(
        name=campaign_in.name,
        seed_payload=campaign_in.seed_payload,
        target_host=campaign_in.target_host,
        target_port=campaign_in.target_port,
        source_ip=campaign_in.source_ip,
        protocol=campaign_in.protocol,
        direction=campaign_in.direction,
        mutation_count=campaign_in.mutation_count,
        status=CampaignStatus.CREATED,
    )
    db.add(campaign)
    db.flush()  # Get the auto-generated ID without committing

    campaign_id = campaign.id
    protocol_val = campaign_in.protocol.value
    total_count = campaign_in.mutation_count

    # ── Step 2: Generate & store payloads in batches ───────────────────
    # For large counts (millions), we generate in chunks of 10K to avoid
    # holding millions of dicts in memory simultaneously.
    BATCH_SIZE = 10_000
    total_stored = 0
    remaining = total_count

    try:
        while remaining > 0:
            chunk_size = min(BATCH_SIZE, remaining)

            # Generate a chunk of mutations
            mutations = mutate_seed(
                seed_json=campaign_in.seed_payload,
                count=chunk_size,
                protocol=protocol_val,
            )

            # Bulk insert this chunk
            payload_objects = []
            for mutation in mutations:
                payload_objects.append(Payload(
                    campaign_id=campaign_id,
                    content=mutation["content"],
                    mutation_type=mutation["mutation_type"],
                    size_bytes=mutation["size_bytes"],
                    status=PayloadStatus.PENDING,
                ))

            db.add_all(payload_objects)
            db.flush()  # Write to DB immediately, free memory

            total_stored += len(payload_objects)
            remaining -= chunk_size

            # Log progress every 100K payloads
            if total_stored % 100_000 < BATCH_SIZE:
                logger.info(f"  Campaign '{campaign_in.name}': {total_stored:,}/{total_count:,} payloads generated")

    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    # ── Step 3: Update campaign totals and commit ──────────────────────
    campaign.total_payloads = total_stored
    db.commit()
    db.refresh(campaign)

    logger.info(
        f"Campaign '{campaign.name}' (ID={campaign.id}) created with "
        f"{total_stored:,} mutated payloads"
    )

    return campaign


# ============================================================================
# GET /api/v1/campaigns/ — List all campaigns
# ============================================================================
@router.get("/", response_model=list[CampaignOut])
def list_campaigns(
    status: Optional[CampaignStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
):
    """
    List all campaigns with optional status filtering and pagination.
    Results are ordered by creation date (newest first).
    """
    query = db.query(Campaign)

    if status:
        query = query.filter(Campaign.status == status)

    campaigns = (
        query
        .order_by(Campaign.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return campaigns


# ============================================================================
# GET /api/v1/campaigns/{id} — Get campaign details
# ============================================================================
@router.get("/{campaign_id}", response_model=CampaignOut)
def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
):
    """Get detailed information about a specific campaign."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    return campaign


# ============================================================================
# POST /api/v1/campaigns/{id}/start — Start a campaign
# ============================================================================
@router.post("/{campaign_id}/start", response_model=CampaignOut)
def start_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
):
    """
    Start a fuzzing campaign.

    Transitions the campaign from CREATED → RUNNING.
    Once RUNNING, the attack node can poll for payload batches.

    Only campaigns in CREATED or STOPPED status can be started.
    """
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    if campaign.status not in (CampaignStatus.CREATED, CampaignStatus.STOPPED):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot start campaign in '{campaign.status.value}' status. "
                   f"Only CREATED or STOPPED campaigns can be started."
        )

    campaign.status = CampaignStatus.RUNNING
    campaign.started_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(campaign)

    logger.info(f"Campaign '{campaign.name}' (ID={campaign.id}) started")
    return campaign


# ============================================================================
# POST /api/v1/campaigns/{id}/stop — Stop a campaign
# ============================================================================
@router.post("/{campaign_id}/stop", response_model=CampaignOut)
def stop_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
):
    """
    Stop a running fuzzing campaign.

    Transitions the campaign from RUNNING → STOPPED.
    Pending payloads remain in the database for potential resumption.
    """
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    if campaign.status != CampaignStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop campaign in '{campaign.status.value}' status. "
                   f"Only RUNNING campaigns can be stopped."
        )

    campaign.status = CampaignStatus.STOPPED
    campaign.stopped_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(campaign)

    logger.info(f"Campaign '{campaign.name}' (ID={campaign.id}) stopped")
    return campaign


# ============================================================================
# GET /api/v1/campaigns/{id}/payloads — Get pending payloads for dispatch
# ============================================================================
@router.get("/{campaign_id}/payloads", response_model=PayloadBatchOut)
def get_payload_batch(
    campaign_id: int,
    batch_size: int = Query(50, ge=1, le=500, description="Number of payloads per batch"),
    db: Session = Depends(get_db),
):
    """
    Fetch a batch of PENDING payloads for dispatch to the attack node.

    This is the endpoint that the Java attack node polls periodically.
    It returns the next batch_size payloads that haven't been sent yet.

    The payloads are NOT marked as SENT here — that happens when the
    attack node ACKs delivery via the /ack endpoint. This ensures
    at-least-once delivery semantics.
    """
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    if campaign.status != CampaignStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"Campaign is not running (status: {campaign.status.value})"
        )

    # Fetch the next batch of unsent payloads
    payloads = (
        db.query(Payload)
        .filter(
            Payload.campaign_id == campaign_id,
            Payload.status == PayloadStatus.PENDING,
        )
        .order_by(Payload.id.asc())
        .limit(batch_size)
        .all()
    )

    return PayloadBatchOut(
        campaign_id=campaign.id,
        target_host=campaign.target_host,
        target_port=campaign.target_port,
        protocol=campaign.protocol,
        direction=campaign.direction,
        source_ip=campaign.source_ip,
        payloads=[PayloadOut.model_validate(p) for p in payloads],
    )


# ============================================================================
# POST /api/v1/campaigns/{id}/payloads/ack — Acknowledge payload delivery
# ============================================================================
@router.post("/{campaign_id}/payloads/ack")
def acknowledge_payloads(
    campaign_id: int,
    payload_ids: list[int],
    crashed_ids: list[int] = [],
    db: Session = Depends(get_db),
):
    """
    Acknowledge that payloads have been delivered to the target.

    The attack node calls this after firing a batch. It reports:
    - payload_ids: All payload IDs that were sent
    - crashed_ids: Subset of payload_ids that triggered a crash response

    This updates payload statuses and campaign aggregate counters.
    """
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    now = datetime.now(timezone.utc)
    sent_count = 0
    crash_count = 0

    for payload_id in payload_ids:
        payload = db.query(Payload).filter(
            Payload.id == payload_id,
            Payload.campaign_id == campaign_id,
        ).first()

        if payload:
            if payload_id in crashed_ids:
                payload.status = PayloadStatus.CRASH
                crash_count += 1
            else:
                payload.status = PayloadStatus.SENT
            payload.sent_at = now
            sent_count += 1

    # Update campaign aggregate counters
    campaign.payloads_sent += sent_count
    campaign.payloads_crashed += crash_count

    # Check if all payloads have been sent
    remaining = (
        db.query(Payload)
        .filter(
            Payload.campaign_id == campaign_id,
            Payload.status == PayloadStatus.PENDING,
        )
        .count()
    )

    if remaining == 0 and campaign.status == CampaignStatus.RUNNING:
        campaign.status = CampaignStatus.COMPLETED
        campaign.stopped_at = now
        logger.info(f"Campaign '{campaign.name}' (ID={campaign.id}) completed — all payloads sent")

    db.commit()

    return {
        "acknowledged": sent_count,
        "crashes_recorded": crash_count,
        "remaining_payloads": remaining,
        "campaign_status": campaign.status.value,
    }


# ============================================================================
# GET /api/v1/metrics — Dashboard metrics (mounted here for convenience)
# ============================================================================
@router.get("/metrics/dashboard", response_model=DashboardMetrics)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """
    Aggregated metrics for the dashboard frontend.

    Computes real-time statistics across all campaigns for display
    in the Glassmorphism dashboard. Designed for frequent polling
    (every 2-3 seconds) with minimal query overhead.
    """
    total_campaigns = db.query(Campaign).count()
    active_campaigns = (
        db.query(Campaign)
        .filter(Campaign.status == CampaignStatus.RUNNING)
        .count()
    )

    # Aggregate payload stats across all campaigns
    total_generated = sum(
        c.total_payloads for c in db.query(Campaign).all()
    )
    total_sent = sum(
        c.payloads_sent for c in db.query(Campaign).all()
    )
    total_crashes = sum(
        c.payloads_crashed for c in db.query(Campaign).all()
    )

    # Crash rate as a percentage of sent payloads
    crash_rate = (total_crashes / total_sent * 100) if total_sent > 0 else 0.0

    # Recent crash reports for the triage table
    recent_crashes = (
        db.query(CrashReport)
        .order_by(CrashReport.timestamp.desc())
        .limit(20)
        .all()
    )

    return DashboardMetrics(
        total_campaigns=total_campaigns,
        active_campaigns=active_campaigns,
        total_payloads_generated=total_generated,
        total_payloads_sent=total_sent,
        total_crashes_detected=total_crashes,
        crash_rate_percent=round(crash_rate, 2),
        recent_crashes=[CrashReportOut.model_validate(c) for c in recent_crashes],
    )
