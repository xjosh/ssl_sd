from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .config import Config
from . import database as db
from .scanner import run_scan

logger = logging.getLogger(__name__)

_scanning = False
_config: Optional[Config] = None


def set_config(config: Config) -> None:
    global _config
    _config = config


def is_scanning() -> bool:
    return _scanning


async def execute_scan(config: Optional[Config] = None) -> Optional[int]:
    """
    Run a single full scan cycle.  Safe to call concurrently — a second
    call while a scan is running returns None immediately.
    """
    global _scanning

    if _scanning:
        logger.warning("Scan already running; skipping trigger")
        return None

    cfg = config or _config
    if not cfg:
        logger.error("No config loaded; cannot scan")
        return None

    _scanning = True
    scan_id = await db.create_scan()

    # Load specs from DB at scan time so changes take effect without restart
    from .config import IPSpec
    raw_specs = await db.get_specs(enabled_only=True)
    if not raw_specs:
        logger.warning("Scan %d: no enabled specs in DB; nothing to scan", scan_id)
        await db.complete_scan(scan_id, 0, 0, 0, 0, status="completed")
        _scanning = False
        return scan_id

    ip_specs = [IPSpec(descriptor=s["descriptor"], spec=s["spec"]) for s in raw_specs]
    scan_cfg = cfg.model_copy(update={"specs": ip_specs})

    logger.info("Scan %d started (workers=%d, ports=%d-%d, specs=%d)",
                scan_id, scan_cfg.max_workers,
                scan_cfg.port_range.start, scan_cfg.port_range.end,
                len(ip_specs))
    try:
        seen_keys: set = set()
        new_count = 0

        async def on_found(host: str, port: int, descriptor: str, tls_info: dict) -> None:
            nonlocal new_count
            outcome = await db.upsert_target(host, port, descriptor, tls_info)
            seen_keys.add((host, port))
            if outcome == "new":
                new_count += 1

        results = await run_scan(scan_cfg, on_found=on_found)

        deactivated = await db.mark_unseen_inactive(
            seen_keys, results["scanned_hosts"]
        )

        await db.complete_scan(
            scan_id,
            hosts_scanned=results["hosts_scanned"],
            targets_found=results["targets_found"],
            new_targets=new_count,
            deactivated=deactivated,
            status="completed",
        )
        logger.info(
            "Scan %d complete: %d targets (%d new, %d deactivated)",
            scan_id, results["targets_found"], new_count, deactivated,
        )
        return scan_id

    except Exception as exc:
        logger.error("Scan %d failed: %s", scan_id, exc, exc_info=True)
        await db.complete_scan(scan_id, 0, 0, 0, 0, status="failed")
        return scan_id
    finally:
        _scanning = False


async def scan_loop(config: Config) -> None:
    """Background task: scan on startup, then repeat at config.scan_interval."""
    set_config(config)
    while True:
        await execute_scan(config)
        logger.info("Next scan in %ds", config.scan_interval)
        await asyncio.sleep(config.scan_interval)
