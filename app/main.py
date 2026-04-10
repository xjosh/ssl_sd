from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import load_config
from . import database as db
from .scheduler import scan_loop
from .routes import api, sd, ui

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    db.init(config.db_path)
    await db.setup()

    # One-time migration: seed DB specs from config.yaml if specs table is empty
    if config.specs:
        imported = await db.import_specs(config.specs)
        if imported:
            logger.info("Migrated %d spec(s) from config.yaml into DB", imported)

    logger.info(
        "ssl_sd starting | interval=%ds workers=%d ports=%d-%d",
        config.scan_interval,
        config.max_workers,
        config.port_range.start,
        config.port_range.end,
    )

    loop_task = asyncio.create_task(scan_loop(config))
    yield
    loop_task.cancel()
    try:
        await loop_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="SSL Service Discovery",
    description="HTTP service discovery for Prometheus ssl_exporter",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(sd.router)
app.include_router(api.router)
app.include_router(ui.router)
