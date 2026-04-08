from fastapi import APIRouter
from .. import database as db

router = APIRouter()


@router.get("/sd", summary="Prometheus HTTP service discovery endpoint")
async def service_discovery():
    """
    Returns active HTTPS targets in Prometheus HTTP SD format.

    Suggested prometheus.yml snippet:

        - job_name: "ssl"
          metrics_path: /probe
          http_sd_configs:
            - url: http://ssl-sd:8080/sd
          relabel_configs:
            - source_labels: [__address__]
              target_label: __param_target
            - source_labels: [__param_target]
              target_label: instance
            - target_label: __address__
              replacement: ssl-exporter:9219
    """
    targets = await db.get_targets(status="active")

    return [
        {
            "targets": [f"{t['ip']}:{t['port']}"],
            "labels": {
                "descriptor": t.get("descriptor") or "",
                "self_signed": "true" if t.get("self_signed") else "false",
            },
        }
        for t in targets
    ]
