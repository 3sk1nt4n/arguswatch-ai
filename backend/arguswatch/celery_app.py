"""
ArgusWatch Celery Configuration - v14
======================================
REAL scheduled tasks that actually work:

1. Intel collection: calls intel-proxy HTTP API every 4h (NOT local collectors)
2. Customer matching: runs match_all_customers every 30min after collection
3. Correlation: routes unmatched detections to customers every 15min
4. Attribution: links findings to threat actors every 30min
5. Exposure scoring: recalculates risk scores every 1h
6. Alert check: scans for SLA breaches and dispatches alerts every 15min

The old beat_schedule referenced local backend collectors that need internet
access - but the backend container doesn't have internet access.
In v13+, ALL collection goes through intel-proxy (which has internet).
"""

import os
import logging
from celery import Celery
from celery.schedules import crontab
from arguswatch.config import settings

logger = logging.getLogger("arguswatch.celery")

celery_app = Celery(
    "arguswatch",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_hijack_root_logger=False,
    # Prevent tasks from running forever
    task_soft_time_limit=300,   # 5 min soft limit
    task_time_limit=600,        # 10 min hard kill
    beat_schedule={
        # ═══════════════════════════════════════════════════════════
        # COLLECTION via Intel Proxy (the only path with internet)
        # ═══════════════════════════════════════════════════════════
        "intel-proxy-collect-all-4h": {
            "task": "arguswatch.tasks.collect_via_intel_proxy",
            "schedule": 3600.0,  # V16.4.5: every 1 hour (was 4h - too slow for demos)
            "kwargs": {"endpoint": "all"},
        },

        # ═══════════════════════════════════════════════════════════
        # CUSTOMER INTEL MATCHING - the critical bridge
        # Runs 5min after collection to match new IOCs to customer assets
        # ═══════════════════════════════════════════════════════════
        "match-all-customers-30m": {
            "task": "arguswatch.tasks.match_all_customers_task",
            "schedule": 1800.0,  # 30 min
        },

        # ═══════════════════════════════════════════════════════════
        # CORRELATION - routes unmatched detections to customers
        # ═══════════════════════════════════════════════════════════
        "correlate-detections-15m": {
            "task": "arguswatch.tasks.correlate_detections_task",
            "schedule": 900.0,  # 15 min
        },

        # ═══════════════════════════════════════════════════════════
        # ATTRIBUTION - link findings to threat actors
        # ═══════════════════════════════════════════════════════════
        "attribution-pass-30m": {
            "task": "arguswatch.engine.attribution_engine.run_attribution_task",
            "schedule": 1800.0,
        },

        # ═══════════════════════════════════════════════════════════
        # THREAT PRESSURE - convert unmatched IOCs into sector risk
        # Class 2/3 IOCs that can't match customers directly
        # ═══════════════════════════════════════════════════════════
        "threat-pressure-1h": {
            "task": "arguswatch.tasks.threat_pressure_task",
            "schedule": 3600.0,
        },

        # ═══════════════════════════════════════════════════════════
        # EXPOSURE SCORING - recalculate with 3-layer model
        # ═══════════════════════════════════════════════════════════
        "exposure-recalc-1h": {
            "task": "arguswatch.tasks.exposure_recalc_task",
            "schedule": 3600.0,
        },

        # ═══════════════════════════════════════════════════════════
        # ALERT CHECK - scan for SLA breaches and unalerted findings
        # ═══════════════════════════════════════════════════════════
        "alert-sla-check-15m": {
            "task": "arguswatch.tasks.check_sla_and_alert_task",
            "schedule": 900.0,
        },

        # ═══════════════════════════════════════════════════════════
        # STIX / SIEM - export and forward
        # ═══════════════════════════════════════════════════════════
        "stix-export-1h": {
            "task": "arguswatch.engine.stix_exporter.run_stix_export_task",
            "schedule": 3600.0,
        },
        "siem-forward-15m": {
            "task": "arguswatch.engine.syslog_exporter.run_syslog_task",
            "schedule": 900.0,
        },

        # ═══════════════════════════════════════════════════════════
        # PIPELINE BATCH - catch-all for missed detections
        # ═══════════════════════════════════════════════════════════
        "pipeline-batch-5m": {
            "task": "arguswatch.services.ingest_pipeline.process_new_detections_batch",
            "schedule": 300.0,
        },
        "recheck-findings-hourly": {
            "task": "arguswatch.services.ingest_pipeline.recheck_open_findings",
            "schedule": 3600.0,
        },

        # ═══════════════════════════════════════════════════════════
        # EXPOSURE HISTORY - daily snapshot for trend charts
        # ═══════════════════════════════════════════════════════════
        "exposure-snapshot-daily": {
            "task": "arguswatch.tasks.snapshot_exposure_history",
            "schedule": 86400.0,  # 24 hours
        },

        # ═══════════════════════════════════════════════════════════
        # V16.4: AGENTIC AI TASKS
        # ═══════════════════════════════════════════════════════════
        "darkweb-triage-30min": {
            "task": "arguswatch.tasks.darkweb_triage_task",
            "schedule": 1800.0,  # 30 min - triage untriaged dark web mentions
        },
        "sector-detection-6h": {
            "task": "arguswatch.tasks.sector_campaign_detection_task",
            "schedule": 21600.0,  # 6 hours - cross-customer IOC correlation
        },
    },
)

celery_app.autodiscover_tasks([
    "arguswatch.tasks",
    "arguswatch.collectors",
    "arguswatch.collectors._pipeline_hook",
    "arguswatch.collectors.enterprise",
    "arguswatch.engine",
    "arguswatch.services",
])
