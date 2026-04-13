from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import timezone
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .config import Config, IPSpec

logger = logging.getLogger(__name__)

OnFoundCallback = Callable[[str, int, str, Dict], Awaitable[None]]


# ---------------------------------------------------------------------------
# Low-level probes
# ---------------------------------------------------------------------------

async def _host_alive(host: str, ports: List[int], timeout: float) -> bool:
    """
    Quick host-alive pre-check using TCP.

    Returns True as soon as any probe port responds — either by accepting the
    connection (port open) or by sending a TCP RST (port closed but host up).
    Returns False only when every probe port times out, which strongly suggests
    the host is down or fully firewalled.

    This distinction matters: ConnectionRefusedError (RST) means the IP is
    reachable even if none of the probe ports are open, so we still want to
    do the full port scan.
    """
    for port in ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True          # port accepted — definitely alive
        except ConnectionRefusedError:
            return True          # RST received — host is up, port just closed
        except asyncio.TimeoutError:
            continue             # no response on this port, try next
        except OSError:
            continue             # unreachable / network error, try next
        except Exception:
            continue
    return False                 # all probe ports timed out


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
# Scan runner
# ---------------------------------------------------------------------------

async def run_scan(config: Config, on_found: Optional[OnFoundCallback] = None) -> Dict:
    """
    Two-phase scan:

    Phase 1 — Host pre-check (concurrent, fast)
        Try a small set of common TCP ports on every host in the configured
        specs.  Hosts that respond (open or RST) are marked alive.  Hosts
        that time out on every probe port are skipped entirely, avoiding
        connect_timeout × 65535 wasted time per dead IP.

        Dead hosts are NOT added to scanned_hosts, so existing DB targets for
        those hosts are preserved — the host may just be temporarily down.

    Phase 2 — Port scan alive hosts (streamed, bounded concurrency)
        For each alive host, probe every port in the configured range using
        the two-step TCP→TLS approach.  Discovered HTTPS endpoints are
        passed to on_found immediately so callers can persist them without
        waiting for the full scan to complete.

    Concurrency across both phases is shared via a single semaphore bounded
    by config.max_workers.
    """
    semaphore = asyncio.Semaphore(config.max_workers)
    scanned_hosts: Set[str] = set()
    total_probed = 0
    targets_found = 0
    total_errors = 0

    # -------------------------------------------------------------------------
    # Phase 1: collect all hosts from specs, pre-check concurrently
    # -------------------------------------------------------------------------
    all_spec_hosts: List[Tuple[str, str]] = []   # (descriptor, host)
    for spec in config.specs:
        try:
            for host in spec.expand_hosts():
                all_spec_hosts.append((spec.descriptor, host))
        except Exception as exc:
            logger.warning("Skipping spec '%s': %s", spec.spec, exc)

    alive: List[Tuple[str, str]] = []

    if config.precheck_ports:
        logger.info("Phase 1: pre-checking %d hosts on ports %s",
                    len(all_spec_hosts), config.precheck_ports)

        async def precheck(descriptor: str, host: str) -> None:
            async with semaphore:
                if await _host_alive(host, config.precheck_ports, config.precheck_timeout):
                    alive.append((descriptor, host))
                else:
                    logger.debug("Host %s skipped (no response to pre-check)", host)

        await asyncio.gather(*[
            asyncio.create_task(precheck(d, h)) for d, h in all_spec_hosts
        ])

        skipped = len(all_spec_hosts) - len(alive)
        logger.info("Phase 1 complete: %d/%d hosts alive, %d skipped",
                    len(alive), len(all_spec_hosts), skipped)
    else:
        # Pre-check disabled — scan everything
        alive = all_spec_hosts

    # -------------------------------------------------------------------------
    # Phase 2: port scan alive hosts with streaming back-pressure
    # -------------------------------------------------------------------------
    logger.info("Phase 2: scanning %d hosts × %d ports",
                len(alive), config.port_range.end - config.port_range.start + 1)

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

    # Stream task creation — keep at most max_workers * 4 tasks pending
    # to avoid holding millions of coroutines in memory for large scopes.
    pending: Set[asyncio.Task] = set()
    high_water = config.max_workers * 4

    for descriptor, host in alive:
        for port in range(config.port_range.start, config.port_range.end + 1):
            task = asyncio.create_task(probe(descriptor, host, port))
            pending.add(task)
            task.add_done_callback(pending.discard)
            while len(pending) >= high_water:
                await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    return {
        "scanned_hosts": scanned_hosts,
        "hosts_scanned": len(scanned_hosts),
        "hosts_checked": len(all_spec_hosts),
        "hosts_skipped": len(all_spec_hosts) - len(alive),
        "total_probed": total_probed,
        "targets_found": targets_found,
        "errors": total_errors,
    }
