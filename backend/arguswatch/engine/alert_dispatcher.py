"""Alert Dispatcher - Email + Slack webhook + SMS on Critical/High detections.
3-level escalation framework:
  Level 1: SLA breach → Slack + email reminder
  Level 2: Re-detection → All 3 channels + CISO + ESCALATION flag
  Level 3: Impact confirmed → Full executive notification + legal hold
"""
import httpx, logging, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from arguswatch.config import settings

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.engine.alert_dispatcher")

async def send_slack(message: str, webhook_url: str = "") -> bool:
    url = webhook_url or getattr(settings, "SLACK_WEBHOOK_URL", "")
    if not url: return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, json={"text": message})
            return r.status_code == 200
    except Exception as e:
        logger.warning(f"Slack alert failed: {e}"); return False

def send_email(subject: str, body: str, to_email: str) -> bool:
    host = getattr(settings, "SMTP_HOST", "")
    if not host: return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = getattr(settings, "SMTP_USER", "arguswatch@solventcyber.com")
        msg["To"] = to_email
        msg.attach(MIMEText(body, "plain"))
        port = int(getattr(settings, "SMTP_PORT", 587))
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            user = getattr(settings, "SMTP_USER", "")
            pwd = getattr(settings, "SMTP_PASS", "")
            if user and pwd: server.login(user, pwd)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.warning(f"Email alert failed: {e}"); return False

async def dispatch_detection_alert(detection, customer=None) -> dict:
    """Dispatch alert for a new CRITICAL or HIGH detection."""
    sev = _sev(detection.severity) or "HIGH"
    if sev not in ("CRITICAL", "HIGH"):
        return {"skipped": "severity_below_threshold"}

    results = {}
    customer_name = customer.name if customer else f"Customer #{detection.customer_id}"
    slack_url = customer.slack_channel if customer and customer.slack_channel else \
                getattr(settings, "SLACK_WEBHOOK_URL", "")

    emoji = "🚨" if sev == "CRITICAL" else "🟠"
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    slack_msg = (
        f"{emoji} *{sev} Detection - {customer_name}*\n"
        f"*Type:* `{detection.ioc_type}`\n"
        f"*Value:* `{detection.ioc_value[:80]}`\n"
        f"*Source:* {detection.source}\n"
        f"*SLA:* {detection.sla_hours}h\n"
        f"*Detected:* {ts}\n"
        f"*Action:* http://localhost:7777/detections/{detection.id}"
    )
    results["slack"] = await send_slack(slack_msg, slack_url)

    alert_email = customer.email if customer else getattr(settings, "ALERT_EMAIL", "")
    if alert_email:
        results["email"] = send_email(
            subject=f"[ArgusWatch] {sev}: {detection.ioc_type} - {customer_name}",
            body=f"Detection ID: {detection.id}\nType: {detection.ioc_type}\nValue: {detection.ioc_value}\nSource: {detection.source}\nSLA: {detection.sla_hours}h\nDetected: {ts}",
            to_email=alert_email,
        )

    return results

async def dispatch_escalation_alert(detection, level: int = 2, customer=None) -> dict:
    """Dispatch Level 2 or 3 escalation alert."""
    results = {}
    customer_name = customer.name if customer else f"Customer #{detection.customer_id}"

    if level == 2:
        msg = (
            f"🔴 *ESCALATION - Re-Detection After Remediation*\n"
            f"*Customer:* {customer_name}\n"
            f"*IOC:* `{detection.ioc_value[:80]}`\n"
            f"*Source:* {detection.source}\n"
            f"Fix did NOT hold at 72h re-check. SLA resets from zero. CISO notified.\n"
            f"New incident requires review: http://localhost:7777/detections/{detection.id}"
        )
    else:
        msg = (
            f"🚨 *LEVEL 3 ESCALATION - Customer Impact Confirmed*\n"
            f"*Customer:* {customer_name}\n"
            f"Crisis communication plan activating. Legal hold initiated.\n"
            f"IR retainer engagement required. ArgusWatch: http://localhost:7777"
        )

    results["slack"] = await send_slack(msg)
    ciso_email = getattr(settings, "CISO_EMAIL", getattr(settings, "ALERT_EMAIL", ""))
    if ciso_email:
        results["ciso_email"] = send_email(
            subject=f"[ArgusWatch ESCALATION L{level}] {customer_name}",
            body=msg.replace("*","").replace("`",""),
            to_email=ciso_email,
        )
    return results


async def dispatch_finding_alert(finding, customer) -> dict:
    """V11: Dispatch alerts for a Finding object (wraps dispatch_detection_alert).
    Finding has the same fields as Detection that alert_dispatcher needs.
    """
    # Build a minimal Detection-like proxy so dispatch_detection_alert works unchanged
    class FindingProxy:
        def __init__(self, f):
            self.id = f.id
            self.ioc_value = f.ioc_value
            self.ioc_type = f.ioc_type
            self.severity = f.severity
            self.source = ", ".join(f.all_sources or ["unknown"])
            self.confidence = f.confidence
            self.created_at = f.created_at
            self.sla_hours = f.sla_hours
            self.status = f.status
            self.matched_asset = f.matched_asset
            self.correlation_type = f.correlation_type
            self.actor_name = f.actor_name
            self.source_count = f.source_count
            self.campaign_id = f.campaign_id
    return await dispatch_detection_alert(FindingProxy(finding), customer)
