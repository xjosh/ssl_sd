from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import timezone
from typing import AsyncIterator, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .config import Config, IPSpec

logger = logging.getLogger(__name__)

OnFoundCallback = Callable[[str, int, str, Dict], Awaitable[None]]


# ---------------------------------------------------------------------------
# Low-level probes
# ---------------------------------------------------------------------------

async def _tcp_open(host: str, port: int, timeout: float) -> bool:
    """Return True if TCP connect succeeds within timeout."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _tls_probe(host: str, port: int, timeout: float) -> Optional[Dict]:
    """
    Attempt a TLS handshake on an already-known-open TCP port.
    Returns a dict with cert metadata, or None if the port is not HTTPS.
    Accepts self-signed and expired certificates intentionally.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
        )
    except (ssl.SSLError, asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception as exc:
        logger.debug("TLS connect error %s:%d: %s", host, port, exc)
        return None

    ssl_obj = writer.get_extra_info("ssl_object")
    cert_der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    if not cert_der:
        return {"self_signed": False, "cert_expiry": None,
                "cert_subject": None, "cert_issuer": None}

    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        is_self_signed = cert.issuer == cert.subject

        # cryptography ≥42 exposes timezone-aware not_valid_after_utc
        try:
            expiry = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            expiry = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

        return {
            "self_signed": is_self_signed,
            "cert_expiry": expiry,
            "cert_subject": cert.subject.rfc4514_string(),
            "cert_issuer": cert.issuer.rfc4514_string(),
        }
    except Exception as exc:
        logger.debug("Cert parse error %s:%d: %s", host, port, exc)
        return {"self_signed": False, "cert_expiry": None,
                "cert_subject": None, "cert_issuer": None}


# ---------------------------------------------------------------------------
# Target generator
# ---------------------------------------------------------------------------

async def _iter_targets(
    specs: List[IPSpec], port_start: int, port_end: int
) -> AsyncIterator[Tuple[str, str, int]]:
    """Yield (descriptor, host, port) for every combination in config."""
    for spec in specs:
        try:
            hosts = spec.expand_hosts()
        except Exception as exc:
            logger.warning("Skipping spec '%s': %s", spec.spec, exc)
            continue
        for host in hosts:
            for port in range(port_start, port_end + 1):
                yield spec.descriptor, host, port


# ---------------------------------------------------------------------------
# Scan runner
# ---------------------------------------------------------------------------

async def run_scan(config: Config, on_found: Optional[OnFoundCallback] = None) -> Dict:
    """
    Execute a full scan of all configured IP specs across the configured port
    range.

    When a target is discovered it is passed immediately to ``on_found``
    (if provided) so callers can persist or act on it without waiting for the
    full scan to complete.

    Concurrency is controlled by config.max_workers (semaphore).  Tasks are
    streamed to bound memory usage — at most max_workers * 4 coroutines live
    in memory at once, regardless of how large the address space is.
    """
    semaphore = asyncio.Semaphore(config.max_workers)
    scanned_hosts: Set[str] = set()
    total_probed = 0
    targets_found = 0
    total_errors = 0

    async def probe(descriptor: str, host: str, port: int) -> None:
        nonlocal total_probed, targets_found, total_errors
        async with semaphore:
            scanned_hosts.add(host)
            total_probed += 1
            try:
                if await _tcp_open(host, port, config.connect_timeout):
                    tls = await _tls_probe(host, port, config.tls_timeout)
                    if tls is not None:
                        targets_found += 1
                        logger.info(
                            "HTTPS found: %s:%d [%s] self_signed=%s",
                            host, port, descriptor, tls["self_signed"]
                        )
                        if on_found is not None:
                            await on_found(host, port, descriptor, tls)
            except Exception as exc:
                total_errors += 1
                logger.debug("Probe error %s:%d: %s", host, port, exc)

    # Stream task creation to avoid holding 16M+ coroutines in memory.
    # We keep at most max_workers * 4 tasks pending at any time.
    pending: Set[asyncio.Task] = set()
    high_water = config.max_workers * 4

    async for descriptor, host, port in _iter_targets(
        config.specs, config.port_range.start, config.port_range.end
    ):
        task = asyncio.create_task(probe(descriptor, host, port))
        pending.add(task)
        task.add_done_callback(pending.discard)

        # Back-pressure: wait for some tasks to finish before creating more
        while len(pending) >= high_water:
            await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

    # Drain remaining tasks
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    return {
        "scanned_hosts": scanned_hosts,
        "hosts_scanned": len(scanned_hosts),
        "total_probed": total_probed,
        "targets_found": targets_found,
        "errors": total_errors,
    }
