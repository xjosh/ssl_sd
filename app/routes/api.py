from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import database as db
from .. import scheduler

router = APIRouter(prefix="/api", tags=["api"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TargetCreate(BaseModel):
    ip: str
    port: int
    descriptor: Optional[str] = ""


class TargetPatch(BaseModel):
    status: Optional[str] = None
    descriptor: Optional[str] = None


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

@router.get("/targets")
async def list_targets(status: Optional[str] = None):
    return await db.get_targets(status=status)


@router.post("/targets", status_code=201)
async def create_target(body: TargetCreate):
    """Manually register an HTTPS target without waiting for a scan."""
    outcome = await db.upsert_target(
        body.ip,
        body.port,
        body.descriptor or "",
        {"self_signed": False, "cert_expiry": None,
         "cert_subject": None, "cert_issuer": None},
    )
    return {"result": outcome}


@router.patch("/targets/{target_id}")
async def update_target(target_id: int, body: TargetPatch):
    if body.status is not None:
        if body.status not in ("active", "inactive"):
            raise HTTPException(400, "status must be 'active' or 'inactive'")
        ok = await db.set_target_status(target_id, body.status)
        if not ok:
            raise HTTPException(404, "Target not found")

    if body.descriptor is not None:
        ok = await db.update_target_descriptor(target_id, body.descriptor)
        if not ok:
            raise HTTPException(404, "Target not found")

    return {"updated": True}


@router.delete("/targets/{target_id}")
async def delete_target(target_id: int):
    ok = await db.delete_target(target_id)
    if not ok:
        raise HTTPException(404, "Target not found")
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@router.get("/scans")
async def list_scans(limit: int = 25):
    return await db.get_scans(limit=limit)


@router.post("/scans", status_code=202)
async def trigger_scan():
    """Trigger an immediate scan outside the normal schedule."""
    if scheduler.is_scanning():
        raise HTTPException(409, "A scan is already in progress")
    asyncio.create_task(scheduler.execute_scan())
    return {"message": "Scan started"}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def get_stats():
    return await db.get_stats()
