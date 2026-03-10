"""
ArgusWatch AI v16.4.1 - Prometheus Metrics
Exposes /metrics endpoint for Prometheus scraping.

Metrics exported:
  - arguswatch_http_requests_total (counter) - by method, path, status
  - arguswatch_http_request_duration_seconds (histogram) - by method, path
  - arguswatch_detections_total (gauge) - total detections in DB
  - arguswatch_findings_open (gauge) - open findings count
  - arguswatch_customers_total (gauge) - active customers
  - arguswatch_collectors_last_run (gauge) - per-collector last run timestamp
  - arguswatch_threat_pressure_index (gauge) - current threat pressure score

Usage:
  In main.py: from arguswatch.metrics import setup_metrics
               setup_metrics(app)

Prometheus scrape config:
  - job_name: 'arguswatch'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
"""
import time
import logging
from typing import Callable
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("arguswatch.metrics")

# ── In-memory metric stores (no prometheus_client dependency needed) ──
_counters: dict[str, int] = {}
_histograms: dict[str, list[float]] = {}
_gauges: dict[str, float] = {}


def inc_counter(name: str, labels: dict = None, amount: int = 1):
    key = _label_key(name, labels)
    _counters[key] = _counters.get(key, 0) + amount


def observe_histogram(name: str, value: float, labels: dict = None):
    key = _label_key(name, labels)
    if key not in _histograms:
        _histograms[key] = []
    _histograms[key].append(value)
    # Keep only last 1000 observations to bound memory
    if len(_histograms[key]) > 1000:
        _histograms[key] = _histograms[key][-500:]


def set_gauge(name: str, value: float, labels: dict = None):
    key = _label_key(name, labels)
    _gauges[key] = value


def _label_key(name: str, labels: dict = None) -> str:
    if not labels:
        return name
    parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"{name}{{{parts}}}"


def _format_metrics() -> str:
    """Format all metrics in Prometheus exposition format."""
    lines = []

    # Counters
    emitted_types = set()
    for key, val in sorted(_counters.items()):
        name = key.split("{")[0] if "{" in key else key
        if name not in emitted_types:
            lines.append(f"# TYPE {name} counter")
            emitted_types.add(name)
        lines.append(f"{key} {val}")

    # Gauges
    for key, val in sorted(_gauges.items()):
        name = key.split("{")[0] if "{" in key else key
        if name not in emitted_types:
            lines.append(f"# TYPE {name} gauge")
            emitted_types.add(name)
        lines.append(f"{key} {val}")

    # Histograms (simplified - sum and count only)
    for key, values in sorted(_histograms.items()):
        name = key.split("{")[0] if "{" in key else key
        if name not in emitted_types:
            lines.append(f"# TYPE {name} summary")
            emitted_types.add(name)
        if values:
            lines.append(f"{key}_count {len(values)}")
            lines.append(f"{key}_sum {sum(values):.6f}")

    return "\n".join(lines) + "\n"


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that tracks request count and duration."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path == "/metrics":
            return await call_next(request)

        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        # Normalize path to avoid cardinality explosion
        path = request.url.path
        if path.startswith("/api/"):
            # Replace numeric IDs with {id}
            parts = path.split("/")
            parts = ["{id}" if p.isdigit() else p for p in parts]
            path = "/".join(parts)

        labels = {
            "method": request.method,
            "path": path,
            "status": str(response.status_code),
        }

        inc_counter("arguswatch_http_requests_total", labels)
        observe_histogram("arguswatch_http_request_duration_seconds",
                          duration, {"method": request.method, "path": path})

        return response


async def _update_db_gauges():
    """Refresh DB-backed gauges. Called periodically."""
    try:
        from arguswatch.database import async_session
        from sqlalchemy import text

        async with async_session() as db:
            r = await db.execute(text("SELECT COUNT(*) FROM detections"))
            set_gauge("arguswatch_detections_total", float(r.scalar() or 0))

            r = await db.execute(text(
                "SELECT COUNT(*) FROM findings WHERE status IN ('NEW', 'ENRICHED', 'ALERTED', 'ESCALATION')"))
            set_gauge("arguswatch_findings_open", float(r.scalar() or 0))

            r = await db.execute(text("SELECT COUNT(*) FROM customers"))
            set_gauge("arguswatch_customers_total", float(r.scalar() or 0))

            r = await db.execute(text(
                "SELECT collector_name, MAX(started_at) FROM collector_runs GROUP BY collector_name"))
            for row in r.fetchall():
                set_gauge("arguswatch_collectors_last_run",
                          row[1].timestamp() if row[1] else 0,
                          {"source": row[0]})
    except Exception as e:
        logger.debug(f"Metrics DB gauge refresh error: {e}")


def setup_metrics(app: FastAPI):
    """Wire metrics middleware and /metrics endpoint into the app."""

    app.add_middleware(MetricsMiddleware)

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint():
        # Refresh DB gauges on each scrape
        await _update_db_gauges()
        return Response(content=_format_metrics(), media_type="text/plain; charset=utf-8")

    logger.info("Prometheus metrics enabled at /metrics")
