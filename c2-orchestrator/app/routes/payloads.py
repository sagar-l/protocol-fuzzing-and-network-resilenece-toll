# ============================================================================
# FuzzStrike C2 Orchestrator — Seed Payload Routes
# ============================================================================
# Endpoints for managing seed payloads independently of campaigns.
# Useful for testing the mutation engine in isolation.
#
# Route Map:
#   POST /api/v1/payloads/seed/preview → Preview mutations without saving
# ============================================================================

from fastapi import APIRouter, HTTPException
from loguru import logger

from app.models import SeedPayloadIn
from app.mutator import mutate_seed, get_available_strategies

router = APIRouter(prefix="/api/v1/payloads", tags=["Payloads"])


# ============================================================================
# POST /api/v1/payloads/seed/preview — Preview seed mutations
# ============================================================================
@router.post("/seed/preview")
def preview_mutations(
    seed: SeedPayloadIn,
    count: int = 10,
):
    """
    Preview what the mutation engine would generate from a given seed.

    This endpoint is useful for:
    - Testing seed payloads before creating a full campaign
    - Debugging mutation strategies
    - Understanding what payloads will be generated

    The mutations are NOT stored in the database — this is a dry run.

    Args:
        seed: The JSON seed payload to mutate.
        count: Number of mutations to preview (default: 10, max: 100).

    Returns:
        dict: Contains the mutations list and metadata about the run.
    """
    # Clamp count to a reasonable preview limit
    count = min(count, 100)

    logger.info(f"Preview mutation request: {count} payloads from seed")

    try:
        mutations = mutate_seed(seed_json=seed.content, count=count)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Group mutations by strategy for summary
    strategy_counts = {}
    for m in mutations:
        strategy = m["mutation_type"]
        strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1

    return {
        "seed": seed.content,
        "total_mutations": len(mutations),
        "total_size_bytes": sum(m["size_bytes"] for m in mutations),
        "strategy_distribution": strategy_counts,
        "mutations": mutations,
    }


# ============================================================================
# GET /api/v1/payloads/strategies — List available mutation strategies
# ============================================================================
@router.get("/strategies")
def list_strategies():
    """
    List all registered mutation strategies.

    Returns the strategy names that the mutation engine can use.
    Useful for the dashboard to display strategy distribution charts.
    """
    strategies = get_available_strategies()
    return {
        "count": len(strategies),
        "strategies": strategies,
    }
