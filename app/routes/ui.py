from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import database as db
from .. import scheduler

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Jinja2 filters
# ---------------------------------------------------------------------------

def _days_until(dt_str: Optional[str]) -> Optional[int]:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None


def _fmt_dt(dt_str: Optional[str]) -> str:
    if not dt_str:
        return "—"
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return dt_str or "—"


def _scan_duration(scan: dict) -> str:
    if not scan.get("completed_at") or not scan.get("started_at"):
        return "—"
    try:
        start = datetime.fromisoformat(scan["started_at"])
        end = datetime.fromisoformat(scan["completed_at"])
        secs = int((end - start).total_seconds())
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "—"


templates.env.filters["days_until"] = _days_until
templates.env.filters["fmt_dt"] = _fmt_dt
templates.env.globals["scan_duration"] = _scan_duration


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = await db.get_stats()
    scans = await db.get_scans(limit=5)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "stats": stats,
        "scans": scans,
        "scanning": scheduler.is_scanning(),
        "scan_duration": _scan_duration,
    })


@router.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request, status: str = ""):
    targets = await db.get_targets(status=status or None)
    return templates.TemplateResponse("targets.html", {
        "request": request,
        "targets": targets,
        "status_filter": status,
        "scanning": scheduler.is_scanning(),
    })


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    scans = await db.get_scans(limit=50)
    return templates.TemplateResponse("scans.html", {
        "request": request,
        "scans": scans,
        "scanning": scheduler.is_scanning(),
        "scan_duration": _scan_duration,
    })


# ---------------------------------------------------------------------------
# Target form actions
# ---------------------------------------------------------------------------

@router.post("/targets/add")
async def add_target(
    ip: str = Form(...),
    port: int = Form(...),
    descriptor: str = Form(""),
):
    await db.upsert_target(
        ip, port, descriptor,
        {"self_signed": False, "cert_expiry": None,
         "cert_subject": None, "cert_issuer": None},
    )
    return RedirectResponse("/targets", status_code=303)


@router.post("/targets/{target_id}/delete")
async def delete_target(target_id: int):
    await db.delete_target(target_id)
    return RedirectResponse("/targets", status_code=303)


@router.post("/targets/{target_id}/activate")
async def activate_target(target_id: int):
    await db.set_target_status(target_id, "active")
    return RedirectResponse("/targets", status_code=303)


@router.post("/targets/{target_id}/deactivate")
async def deactivate_target(target_id: int):
    await db.set_target_status(target_id, "inactive")
    return RedirectResponse("/targets", status_code=303)


# ---------------------------------------------------------------------------
# Specs page
# ---------------------------------------------------------------------------

@router.get("/specs", response_class=HTMLResponse)
async def specs_page(request: Request):
    specs = await db.get_specs()
    return templates.TemplateResponse("specs.html", {
        "request": request,
        "specs": specs,
        "scanning": scheduler.is_scanning(),
    })


@router.post("/specs/add")
async def add_spec(
    descriptor: str = Form(...),
    spec: str = Form(...),
):
    from ..config import IPSpec
    try:
        IPSpec(descriptor=descriptor, spec=spec).expand_hosts()
    except ValueError as exc:
        # Redirect back with an error — keep it simple for now
        return RedirectResponse(f"/specs?error={exc}", status_code=303)
    await db.create_spec(descriptor, spec)
    return RedirectResponse("/specs", status_code=303)


@router.post("/specs/{spec_id}/delete")
async def delete_spec(spec_id: int):
    await db.delete_spec(spec_id)
    return RedirectResponse("/specs", status_code=303)


@router.post("/specs/{spec_id}/enable")
async def enable_spec(spec_id: int):
    await db.update_spec(spec_id, enabled=True)
    return RedirectResponse("/specs", status_code=303)


@router.post("/specs/{spec_id}/disable")
async def disable_spec(spec_id: int):
    await db.update_spec(spec_id, enabled=False)
    return RedirectResponse("/specs", status_code=303)


# ---------------------------------------------------------------------------
# Scan actions
# ---------------------------------------------------------------------------

@router.post("/scans/trigger")
async def trigger_scan():
    if not scheduler.is_scanning():
        asyncio.create_task(scheduler.execute_scan())
    return RedirectResponse("/", status_code=303)
