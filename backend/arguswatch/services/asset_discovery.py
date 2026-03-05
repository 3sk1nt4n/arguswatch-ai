"""
Asset Discovery Connectors - auto-populate customer assets from infrastructure data.

V13 GAP 1 + GAP 7 FIX: Provides offline-capable asset discovery without internet egress.

Connectors:
  1. CSV/JSON bulk import  - operator uploads a file
  2. BIND zone file parser - reads DNS zone exports
  3. DHCP lease parser     - reads ISC dhcpd.leases format
  4. CT log snapshot       - parses Certificate Transparency JSON dumps
  5. Agent bundle ingest   - accepts signed agent telemetry bundles

All connectors output normalized AssetRecord objects that feed into CustomerAsset table.
"""
import csv
import io
import json
import re
import hashlib
import hmac
import logging
import ipaddress
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger("arguswatch.discovery")


# ═══════════════════════════════════════════════════════════════════════
# CANONICAL ASSET RECORD - all connectors output this
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AssetRecord:
    """Normalized asset record. All discovery connectors emit these."""
    asset_type: str          # domain, ip, email, cidr, subdomain, tech_stack, etc.
    asset_value: str         # the actual value
    criticality: str = "medium"  # critical, high, medium, low
    source: str = ""         # which connector found this (bind_zone, dhcp, csv, ct_log, agent)
    discovered_at: str = ""  # ISO timestamp
    confidence: float = 1.0  # 0.0–1.0 - how confident we are this belongs to the customer
    raw_data: dict = field(default_factory=dict)  # original record for audit trail

    def __post_init__(self):
        self.asset_value = self.asset_value.strip().lower()
        if not self.discovered_at:
            self.discovered_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════
# AGENT SCHEMA - canonical format for agent telemetry bundles
# ═══════════════════════════════════════════════════════════════════════

AGENT_SCHEMA = {
    "version": "1.0",
    "fields": {
        "agent_id": "Unique agent identifier (UUID)",
        "hostname": "Machine hostname",
        "fqdn": "Fully qualified domain name",
        "local_ips": "List of local IP addresses",
        "dns_cache": "List of {name, ip, ttl} from local resolver cache",
        "tls_certs": "List of {subject, san_domains, issuer, expiry} from local cert store",
        "listening_ports": "List of {port, protocol, process, pid}",
        "arp_table": "List of {ip, mac, interface}",
        "routes": "List of {destination, gateway, interface}",
        "os_info": "OS name and version",
        "collected_at": "ISO 8601 timestamp",
        "signature": "HMAC-SHA256 of JSON payload (excluding signature field)",
    },
    "example": {
        "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "hostname": "web-prod-01",
        "fqdn": "web-prod-01.newcustomer.com",
        "local_ips": ["10.0.1.50", "192.168.1.100"],
        "dns_cache": [
            {"name": "api.newcustomer.com", "ip": "10.0.1.10", "ttl": 300},
            {"name": "db.newcustomer.com", "ip": "10.0.1.20", "ttl": 600},
        ],
        "tls_certs": [
            {"subject": "*.newcustomer.com", "san_domains": ["newcustomer.com", "*.newcustomer.com"],
             "issuer": "Let's Encrypt", "expiry": "2026-06-01T00:00:00Z"},
        ],
        "listening_ports": [
            {"port": 443, "protocol": "tcp", "process": "nginx", "pid": 1234},
            {"port": 5432, "protocol": "tcp", "process": "postgres", "pid": 5678},
        ],
        "arp_table": [
            {"ip": "10.0.1.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0"},
        ],
        "routes": [
            {"destination": "0.0.0.0/0", "gateway": "10.0.1.1", "interface": "eth0"},
        ],
        "os_info": "Ubuntu 24.04 LTS",
        "collected_at": "2026-03-01T12:00:00Z",
        "signature": "hmac-sha256-hex-string",
    },
}


# ═══════════════════════════════════════════════════════════════════════
# CONNECTOR 1: CSV/JSON BULK IMPORT
# ═══════════════════════════════════════════════════════════════════════

def parse_csv_import(content: str | bytes, default_criticality: str = "medium") -> list[AssetRecord]:
    """Parse CSV with columns: asset_type, asset_value, [criticality].
    Accepts flexible column names: type/asset_type, value/asset_value, etc."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    records = []
    reader = csv.DictReader(io.StringIO(content))

    # Normalize column names
    type_col = None
    value_col = None
    crit_col = None
    if reader.fieldnames:
        for col in reader.fieldnames:
            cl = col.strip().lower().replace(" ", "_")
            if cl in ("asset_type", "type", "category"):
                type_col = col
            elif cl in ("asset_value", "value", "asset", "indicator", "ioc"):
                value_col = col
            elif cl in ("criticality", "crit", "priority", "severity"):
                crit_col = col

    if not type_col or not value_col:
        # Try positional: first col = type, second = value
        if reader.fieldnames and len(reader.fieldnames) >= 2:
            type_col = reader.fieldnames[0]
            value_col = reader.fieldnames[1]
            crit_col = reader.fieldnames[2] if len(reader.fieldnames) > 2 else None
        else:
            return []

    for row in reader:
        atype = (row.get(type_col) or "").strip().lower()
        aval = (row.get(value_col) or "").strip()
        acrit = (row.get(crit_col) or default_criticality).strip().lower() if crit_col else default_criticality

        if not atype or not aval:
            continue

        # Auto-detect type if "auto" or empty
        if atype in ("auto", "detect", ""):
            atype = _auto_detect_type(aval)

        VALID_TYPES = {"domain", "ip", "email", "keyword", "cidr", "org_name", "github_org",
                       "subdomain", "tech_stack", "brand_name", "exec_name", "cloud_asset", "code_repo"}
        if atype not in VALID_TYPES:
            continue

        if acrit not in ("critical", "high", "medium", "low"):
            acrit = default_criticality

        records.append(AssetRecord(
            asset_type=atype, asset_value=aval, criticality=acrit,
            source="csv_import", raw_data=dict(row),
        ))
    return records


def parse_json_import(content: str | bytes) -> list[AssetRecord]:
    """Parse JSON array of {asset_type, asset_value, [criticality]} objects."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        data = data.get("assets", data.get("records", [data]))
    if not isinstance(data, list):
        return []

    records = []
    for item in data:
        if not isinstance(item, dict):
            continue
        atype = str(item.get("asset_type", item.get("type", ""))).strip().lower()
        aval = str(item.get("asset_value", item.get("value", ""))).strip()
        acrit = str(item.get("criticality", item.get("crit", "medium"))).strip().lower()

        if not aval:
            continue
        if not atype or atype in ("auto", "detect"):
            atype = _auto_detect_type(aval)

        records.append(AssetRecord(
            asset_type=atype, asset_value=aval, criticality=acrit,
            source="json_import", raw_data=item,
        ))
    return records


# ═══════════════════════════════════════════════════════════════════════
# CONNECTOR 2: BIND ZONE FILE PARSER
# ═══════════════════════════════════════════════════════════════════════

def parse_bind_zone(content: str | bytes, customer_domain: str = "") -> list[AssetRecord]:
    """Parse BIND-format DNS zone file. Extracts A, AAAA, CNAME, MX, NS, TXT records.
    Returns domains as subdomain assets and IPs as ip assets."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    records = []
    seen = set()
    origin = customer_domain.rstrip(".")

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        # $ORIGIN directive
        if line.upper().startswith("$ORIGIN"):
            parts = line.split()
            if len(parts) >= 2:
                origin = parts[1].rstrip(".")
            continue

        # Parse record: name [ttl] [class] type value
        parts = line.split()
        if len(parts) < 3:
            continue

        # Find the record type
        rtype = None
        rtype_idx = None
        for i, p in enumerate(parts):
            if p.upper() in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "PTR"):
                rtype = p.upper()
                rtype_idx = i
                break

        if not rtype or rtype_idx is None:
            continue

        name = parts[0] if parts[0] != "@" else origin
        if name == "@":
            name = origin
        if not name.endswith(".") and origin and "." not in name:
            name = f"{name}.{origin}"
        name = name.rstrip(".")

        # Extract values
        rvalues = parts[rtype_idx + 1:]
        if not rvalues:
            continue

        if rtype in ("A", "AAAA"):
            ip_val = rvalues[0]
            try:
                ipaddress.ip_address(ip_val)
                key = ("ip", ip_val)
                if key not in seen:
                    seen.add(key)
                    records.append(AssetRecord(
                        asset_type="ip", asset_value=ip_val, criticality="high",
                        source="bind_zone", raw_data={"name": name, "type": rtype, "value": ip_val},
                    ))
            except ValueError:
                pass
            # Also add the hostname as subdomain
            if name and name != origin:
                key = ("subdomain", name)
                if key not in seen:
                    seen.add(key)
                    records.append(AssetRecord(
                        asset_type="subdomain", asset_value=name, criticality="high",
                        source="bind_zone", raw_data={"name": name, "type": rtype},
                    ))

        elif rtype == "CNAME":
            target = rvalues[0].rstrip(".")
            if name and name != origin:
                key = ("subdomain", name)
                if key not in seen:
                    seen.add(key)
                    records.append(AssetRecord(
                        asset_type="subdomain", asset_value=name, criticality="medium",
                        source="bind_zone", raw_data={"name": name, "cname_target": target},
                    ))

        elif rtype == "MX":
            mx_host = rvalues[-1].rstrip(".") if rvalues else ""
            if mx_host:
                key = ("subdomain", mx_host)
                if key not in seen:
                    seen.add(key)
                    records.append(AssetRecord(
                        asset_type="subdomain", asset_value=mx_host, criticality="medium",
                        source="bind_zone", raw_data={"name": name, "mx": mx_host},
                    ))

    return records


# ═══════════════════════════════════════════════════════════════════════
# CONNECTOR 3: DHCP LEASE PARSER (ISC dhcpd.leases format)
# ═══════════════════════════════════════════════════════════════════════

def parse_dhcp_leases(content: str | bytes) -> list[AssetRecord]:
    """Parse ISC DHCP server lease file. Extracts IP-to-hostname mappings."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    records = []
    seen = set()
    current_ip = None
    current_hostname = None
    current_mac = None

    for line in content.splitlines():
        line = line.strip()

        m = re.match(r'^lease\s+([\d.]+)\s*\{', line)
        if m:
            # Save previous lease
            if current_ip and current_ip not in seen:
                seen.add(current_ip)
                records.append(AssetRecord(
                    asset_type="ip", asset_value=current_ip, criticality="medium",
                    source="dhcp_lease",
                    raw_data={"hostname": current_hostname or "", "mac": current_mac or ""},
                ))
            current_ip = m.group(1)
            current_hostname = None
            current_mac = None
            continue

        if line.startswith("client-hostname"):
            m2 = re.search(r'"([^"]+)"', line)
            if m2:
                current_hostname = m2.group(1)

        if line.startswith("hardware ethernet"):
            m3 = re.search(r'([\da-fA-F:]+)', line.split("ethernet")[-1])
            if m3:
                current_mac = m3.group(1)

        if line == "}":
            if current_ip and current_ip not in seen:
                seen.add(current_ip)
                records.append(AssetRecord(
                    asset_type="ip", asset_value=current_ip, criticality="medium",
                    source="dhcp_lease",
                    raw_data={"hostname": current_hostname or "", "mac": current_mac or ""},
                ))
            current_ip = None

    return records


# ═══════════════════════════════════════════════════════════════════════
# CONNECTOR 4: CERTIFICATE TRANSPARENCY LOG PARSER
# ═══════════════════════════════════════════════════════════════════════

def parse_ct_log(content: str | bytes, customer_domains: list[str] = None) -> list[AssetRecord]:
    """Parse Certificate Transparency JSON dump (crt.sh format or similar).
    Filters to only domains matching customer_domains if provided.

    Expected format: JSON array of objects with 'common_name' and/or 'name_value' fields.
    Also accepts newline-delimited JSON."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    customer_domains = [d.lower().rstrip(".") for d in (customer_domains or [])]

    # Try JSON array first, then NDJSON
    try:
        data = json.loads(content)
        if not isinstance(data, list):
            data = [data]
    except json.JSONDecodeError:
        data = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    records = []
    seen = set()

    for entry in data:
        if not isinstance(entry, dict):
            continue

        # Extract domain names from CT entry
        names = set()
        for field_name in ("common_name", "name_value", "subject", "dns_names"):
            val = entry.get(field_name, "")
            if isinstance(val, str):
                for name in val.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and "." in name:
                        names.add(name)
            elif isinstance(val, list):
                for name in val:
                    name = str(name).strip().lower().lstrip("*.")
                    if name and "." in name:
                        names.add(name)

        for name in names:
            # Filter by customer domains if specified
            if customer_domains:
                if not any(name == cd or name.endswith("." + cd) for cd in customer_domains):
                    continue

            if name in seen:
                continue
            seen.add(name)

            records.append(AssetRecord(
                asset_type="subdomain", asset_value=name, criticality="medium",
                source="ct_log", confidence=0.9,
                raw_data={"issuer": entry.get("issuer_name", ""), "not_after": entry.get("not_after", "")},
            ))

    return records


# ═══════════════════════════════════════════════════════════════════════
# CONNECTOR 5: AGENT BUNDLE INGEST
# ═══════════════════════════════════════════════════════════════════════

def parse_agent_bundle(content: str | bytes, signing_key: str = "") -> tuple[list[AssetRecord], dict]:
    """Parse a signed agent telemetry bundle.
    Returns (assets, metadata) where metadata includes agent_id, hostname, etc.
    If signing_key is provided, validates HMAC-SHA256 signature."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    try:
        bundle = json.loads(content)
    except json.JSONDecodeError:
        return [], {"error": "Invalid JSON"}

    if not isinstance(bundle, dict):
        return [], {"error": "Expected JSON object"}

    # Validate signature if key provided
    if signing_key:
        sig = bundle.pop("signature", "")
        payload = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(signing_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return [], {"error": "Invalid signature", "expected": expected[:8] + "..."}
        bundle["signature"] = sig  # restore

    records = []
    seen = set()
    agent_id = bundle.get("agent_id", "unknown")

    # Extract FQDN
    fqdn = bundle.get("fqdn", "")
    if fqdn and fqdn not in seen:
        seen.add(fqdn)
        records.append(AssetRecord(
            asset_type="subdomain", asset_value=fqdn, criticality="high",
            source=f"agent:{agent_id}",
        ))

    # Extract local IPs
    for ip in bundle.get("local_ips", []):
        ip = str(ip).strip()
        if ip and ip not in seen:
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_loopback and not addr.is_link_local:
                    seen.add(ip)
                    records.append(AssetRecord(
                        asset_type="ip", asset_value=ip, criticality="medium",
                        source=f"agent:{agent_id}",
                    ))
            except ValueError:
                pass

    # Extract DNS cache entries
    for entry in bundle.get("dns_cache", []):
        name = str(entry.get("name", "")).strip().lower()
        ip = str(entry.get("ip", "")).strip()
        if name and name not in seen and "." in name:
            seen.add(name)
            records.append(AssetRecord(
                asset_type="subdomain", asset_value=name, criticality="medium",
                source=f"agent:{agent_id}", raw_data=entry,
            ))
        if ip and ip not in seen:
            try:
                ipaddress.ip_address(ip)
                seen.add(ip)
                records.append(AssetRecord(
                    asset_type="ip", asset_value=ip, criticality="low",
                    source=f"agent:{agent_id}",
                ))
            except ValueError:
                pass

    # Extract TLS cert SANs
    for cert in bundle.get("tls_certs", []):
        for san in cert.get("san_domains", []):
            san = str(san).strip().lower().lstrip("*.")
            if san and san not in seen and "." in san:
                seen.add(san)
                records.append(AssetRecord(
                    asset_type="subdomain", asset_value=san, criticality="high",
                    source=f"agent:{agent_id}",
                    raw_data={"issuer": cert.get("issuer", ""), "expiry": cert.get("expiry", "")},
                ))

    # Extract listening services as tech_stack
    for port_info in bundle.get("listening_ports", []):
        proc = str(port_info.get("process", "")).strip()
        port = port_info.get("port", 0)
        if proc and proc not in ("", "-"):
            tech = f"{proc}:{port}" if port else proc
            if tech not in seen:
                seen.add(tech)
                records.append(AssetRecord(
                    asset_type="tech_stack", asset_value=proc, criticality="medium",
                    source=f"agent:{agent_id}", raw_data=port_info,
                ))

    metadata = {
        "agent_id": agent_id,
        "hostname": bundle.get("hostname", ""),
        "fqdn": fqdn,
        "os_info": bundle.get("os_info", ""),
        "collected_at": bundle.get("collected_at", ""),
        "assets_extracted": len(records),
    }
    return records, metadata


# ═══════════════════════════════════════════════════════════════════════
# AUTO-DETECT ASSET TYPE
# ═══════════════════════════════════════════════════════════════════════

def _auto_detect_type(value: str) -> str:
    """Best-effort guess at asset_type from the value string."""
    v = value.strip().lower()

    # IP address
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    # CIDR
    try:
        net = ipaddress.ip_network(v, strict=False)
        if "/" in v:
            return "cidr"
    except ValueError:
        pass

    # Email
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        return "email"

    # Domain (has dots, no spaces, looks like FQDN)
    if re.match(r'^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}$', v):
        return "domain"

    # GitHub/GitLab repo
    if "github.com/" in v or "gitlab.com/" in v:
        return "code_repo"

    # Cloud asset
    if v.startswith("s3://") or v.startswith("gs://") or v.startswith("az://"):
        return "cloud_asset"

    # Default to keyword
    return "keyword"


# ═══════════════════════════════════════════════════════════════════════
# INGEST: Write AssetRecords to DB
# ═══════════════════════════════════════════════════════════════════════

async def ingest_assets(customer_id: int, records: list[AssetRecord]) -> dict:
    """Write discovered assets to CustomerAsset table. Skips duplicates."""
    from arguswatch.database import async_session
    from arguswatch.models import CustomerAsset, AssetType
    from sqlalchemy import select

    async with async_session() as db:
        # Load existing to dedup
        er = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == customer_id))
        existing = {
            (a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type, a.asset_value)
            for a in er.scalars().all()
        }

        added = 0
        skipped = 0
        errors = []
        for rec in records:
            key = (rec.asset_type, rec.asset_value)
            if key in existing:
                skipped += 1
                continue
            try:
                db.add(CustomerAsset(
                    customer_id=customer_id,
                    asset_type=AssetType(rec.asset_type),
                    asset_value=rec.asset_value,
                    criticality=rec.criticality,
                    confidence=rec.confidence,
                    confidence_sources=[rec.source],
                    discovery_source=rec.source,
                ))
                existing.add(key)
                added += 1
            except (ValueError, Exception) as e:
                errors.append(f"{rec.asset_value}: {e}")

        await db.commit()
        return {
            "customer_id": customer_id,
            "added": added,
            "skipped_duplicates": skipped,
            "errors": errors[:10],
            "total_records": len(records),
        }
