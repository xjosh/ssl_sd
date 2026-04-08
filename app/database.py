from __future__ import annotations

import aiosqlite
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

_db_path: str = ""


def init(db_path: str) -> None:
    global _db_path
    _db_path = db_path


@asynccontextmanager
async def _db():
    async with aiosqlite.connect(_db_path) as conn:
        conn.row_factory = aiosqlite.Row
        yield conn


async def setup() -> None:
    async with _db() as conn:
        await conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ip            TEXT    NOT NULL,
                port          INTEGER NOT NULL,
                descriptor    TEXT    NOT NULL DEFAULT '',
                status        TEXT    NOT NULL DEFAULT 'active',
                self_signed   INTEGER NOT NULL DEFAULT 0,
                cert_expiry   TEXT,
                cert_subject  TEXT,
                cert_issuer   TEXT,
                first_seen    TEXT    NOT NULL,
                last_seen     TEXT    NOT NULL,
                last_checked  TEXT,
                UNIQUE(ip, port)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at     TEXT NOT NULL,
                completed_at   TEXT,
                hosts_scanned  INTEGER DEFAULT 0,
                targets_found  INTEGER DEFAULT 0,
                new_targets    INTEGER DEFAULT 0,
                deactivated    INTEGER DEFAULT 0,
                status         TEXT NOT NULL DEFAULT 'running'
            );
        """)
        await conn.commit()


# ---------------------------------------------------------------------------
# Target operations
# ---------------------------------------------------------------------------

async def upsert_target(
    ip: str,
    port: int,
    descriptor: str,
    tls_info: Dict,
) -> str:
    """Insert or update a target. Returns 'new', 'reactivated', or 'updated'."""
    now = _now()
    async with _db() as conn:
        row = await (
            await conn.execute(
                "SELECT id, status FROM targets WHERE ip=? AND port=?", (ip, port)
            )
        ).fetchone()

        if row is None:
            await conn.execute(
                """INSERT INTO targets
                   (ip, port, descriptor, status, self_signed,
                    cert_expiry, cert_subject, cert_issuer,
                    first_seen, last_seen, last_checked)
                   VALUES (?,?,?,'active',?,?,?,?,?,?,?)""",
                (
                    ip, port, descriptor,
                    int(tls_info.get("self_signed", False)),
                    tls_info.get("cert_expiry"),
                    tls_info.get("cert_subject"),
                    tls_info.get("cert_issuer"),
                    now, now, now,
                ),
            )
            await conn.commit()
            return "new"

        was_inactive = row["status"] == "inactive"
        await conn.execute(
            """UPDATE targets
               SET status='active', self_signed=?, cert_expiry=?,
                   cert_subject=?, cert_issuer=?,
                   last_seen=?, last_checked=?, descriptor=?
               WHERE ip=? AND port=?""",
            (
                int(tls_info.get("self_signed", False)),
                tls_info.get("cert_expiry"),
                tls_info.get("cert_subject"),
                tls_info.get("cert_issuer"),
                now, now, descriptor, ip, port,
            ),
        )
        await conn.commit()
        return "reactivated" if was_inactive else "updated"


async def mark_unseen_inactive(
    seen_keys: Set[Tuple[str, int]],
    scanned_hosts: Set[str],
) -> int:
    """
    Deactivate targets whose host was scanned in this cycle but which were
    not found with an active HTTPS endpoint.  Targets outside the scanned
    address space (e.g. manually added) are left untouched.
    """
    now = _now()
    async with _db() as conn:
        rows = await (
            await conn.execute(
                "SELECT id, ip, port FROM targets WHERE status='active'"
            )
        ).fetchall()

        count = 0
        for row in rows:
            if row["ip"] in scanned_hosts and (row["ip"], row["port"]) not in seen_keys:
                await conn.execute(
                    "UPDATE targets SET status='inactive', last_checked=? WHERE id=?",
                    (now, row["id"]),
                )
                count += 1

        await conn.commit()
        return count


async def get_targets(status: Optional[str] = None) -> List[Dict]:
    async with _db() as conn:
        if status:
            cur = await conn.execute(
                "SELECT * FROM targets WHERE status=? ORDER BY descriptor, ip, port",
                (status,),
            )
        else:
            cur = await conn.execute(
                "SELECT * FROM targets ORDER BY descriptor, ip, port"
            )
        return [dict(r) for r in await cur.fetchall()]


async def get_target(target_id: int) -> Optional[Dict]:
    async with _db() as conn:
        row = await (
            await conn.execute("SELECT * FROM targets WHERE id=?", (target_id,))
        ).fetchone()
        return dict(row) if row else None


async def delete_target(target_id: int) -> bool:
    async with _db() as conn:
        cur = await conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        await conn.commit()
        return cur.rowcount > 0


async def set_target_status(target_id: int, status: str) -> bool:
    async with _db() as conn:
        cur = await conn.execute(
            "UPDATE targets SET status=? WHERE id=?", (status, target_id)
        )
        await conn.commit()
        return cur.rowcount > 0


async def update_target_descriptor(target_id: int, descriptor: str) -> bool:
    async with _db() as conn:
        cur = await conn.execute(
            "UPDATE targets SET descriptor=? WHERE id=?", (descriptor, target_id)
        )
        await conn.commit()
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Scan operations
# ---------------------------------------------------------------------------

async def create_scan() -> int:
    async with _db() as conn:
        cur = await conn.execute(
            "INSERT INTO scans (started_at, status) VALUES (?, 'running')", (_now(),)
        )
        await conn.commit()
        return cur.lastrowid


async def complete_scan(
    scan_id: int,
    hosts_scanned: int,
    targets_found: int,
    new_targets: int,
    deactivated: int,
    status: str = "completed",
) -> None:
    async with _db() as conn:
        await conn.execute(
            """UPDATE scans
               SET completed_at=?, hosts_scanned=?, targets_found=?,
                   new_targets=?, deactivated=?, status=?
               WHERE id=?""",
            (_now(), hosts_scanned, targets_found, new_targets, deactivated, status, scan_id),
        )
        await conn.commit()


async def get_scans(limit: int = 25) -> List[Dict]:
    async with _db() as conn:
        cur = await conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in await cur.fetchall()]


async def get_stats() -> Dict:
    async with _db() as conn:
        total = (
            await (await conn.execute("SELECT COUNT(*) FROM targets")).fetchone()
        )[0]
        active = (
            await (
                await conn.execute(
                    "SELECT COUNT(*) FROM targets WHERE status='active'"
                )
            ).fetchone()
        )[0]
        self_signed = (
            await (
                await conn.execute(
                    "SELECT COUNT(*) FROM targets WHERE self_signed=1 AND status='active'"
                )
            ).fetchone()
        )[0]
        last_scan = await (
            await conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
            )
        ).fetchone()

        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "self_signed": self_signed,
            "last_scan": dict(last_scan) if last_scan else None,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
