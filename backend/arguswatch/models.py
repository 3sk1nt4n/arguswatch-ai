"""ArgusWatch ORM - 18 tables. V11: Finding, FindingSource, Campaign, ActorIoc, CveProductMap added."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, BigInteger, String, Text, Float, Boolean, DateTime, ForeignKey, Index, JSON, Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, relationship
import enum

class Base(DeclarativeBase): pass

class SeverityLevel(str, enum.Enum):
    CRITICAL="CRITICAL"; HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; INFO="INFO"

class DetectionStatus(str, enum.Enum):
    NEW="NEW"; ENRICHED="ENRICHED"; ALERTED="ALERTED"; REMEDIATED="REMEDIATED"
    VERIFIED_CLOSED="VERIFIED_CLOSED"; ESCALATION="ESCALATION"
    FALSE_POSITIVE="FALSE_POSITIVE"; CLOSED="CLOSED"

class AssetType(str, enum.Enum):
    DOMAIN="domain"; IP="ip"; EMAIL="email"; KEYWORD="keyword"
    CIDR="cidr"; ORG_NAME="org_name"; GITHUB_ORG="github_org"
    # V10 additions - required for full correlation coverage
    SUBDOMAIN="subdomain"
    TECH_STACK="tech_stack"
    BRAND_NAME="brand_name"
    EXEC_NAME="exec_name"
    CLOUD_ASSET="cloud_asset"
    CODE_REPO="code_repo"
    EMAIL_DOMAIN="email_domain"
    # V16.4: Required for S7 cloud/org matching + Cat 7/12
    AWS_ACCOUNT="aws_account"
    AZURE_TENANT="azure_tenant"
    GCP_PROJECT="gcp_project"
    INTERNAL_DOMAIN="internal_domain"

class User(Base):
    """Persistent user accounts. Replaces the in-memory dict in auth.py."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")  # admin | analyst | viewer
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    last_login = Column(DateTime, nullable=True)


class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    industry = Column(String(100))
    tier = Column(String(20), default="standard")
    primary_contact = Column(String(255))
    email = Column(String(255))
    slack_channel = Column(String(100))
    active = Column(Boolean, default=True)
    # V13: Onboarding state machine - 5 states
    # created -> assets_added -> monitoring -> tuning -> production
    onboarding_state = Column(String(30), default="created")
    onboarding_updated_at = Column(DateTime, nullable=True)
    # V16-fix: Recon status tracking
    recon_status = Column(String(20), default=None)  # pending, success, failed, retrying
    recon_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    updated_at = Column(DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow())
    assets = relationship("CustomerAsset", back_populates="customer", cascade="all, delete-orphan")
    detections = relationship("Detection", back_populates="customer")
    exposures = relationship("CustomerExposure", back_populates="customer", cascade="all, delete-orphan")

class CustomerAsset(Base):
    __tablename__ = "customer_assets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    asset_type = Column(SAEnum(AssetType, values_callable=lambda e: [x.value for x in e]), nullable=False)
    asset_value = Column(String(500), nullable=False)
    criticality = Column(String(20), default="medium")
    # V13: Confidence scoring - tracks how/why this asset was added
    confidence = Column(Float, default=1.0)           # 0.0–1.0 - how sure we are this belongs to the customer
    confidence_sources = Column(JSON, default=list)    # ["analyst", "csv_import", "ct_log", "agent:test-001", "collector:vt"]
    discovery_source = Column(String(100), nullable=True)  # which connector/method added this
    last_seen_in_ioc = Column(DateTime, nullable=True)     # last time a collector saw this in a detection
    ioc_hit_count = Column(Integer, default=0)             # how many detections matched this asset
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    manual_entry = Column(Boolean, default=False)  # V16.4: True if added via manual API
    customer = relationship("Customer", back_populates="assets")
    __table_args__ = (Index("ix_asset_type_value", "asset_type", "asset_value"),)

class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    aliases = Column(JSON, default=list)
    origin_country = Column(String(100))
    motivation = Column(String(100))
    sophistication = Column(String(50))
    active_since = Column(String(20))
    last_seen = Column(String(20))
    target_sectors = Column(JSON, default=list)
    target_countries = Column(JSON, default=list)
    description = Column(Text)
    mitre_id = Column(String(20))
    source = Column(String(50), default="mitre")
    iocs = Column(JSON, default=list)
    techniques = Column(JSON, default=list)
    references = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    updated_at = Column(DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow())
    exposures = relationship("CustomerExposure", back_populates="actor")

class CustomerExposure(Base):
    __tablename__ = "customer_exposure"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    actor_id = Column(Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False)
    exposure_score = Column(Float, default=0.0)
    sector_match = Column(Boolean, default=False)
    detection_count = Column(Integer, default=0)
    darkweb_mentions = Column(Integer, default=0)
    last_calculated = Column(DateTime, default=lambda: datetime.utcnow())
    factor_breakdown = Column(JSON, default=dict)  # V10: {sector_match, cve_score, darkweb_score, etc.}
    recency_multiplier = Column(Float, default=1.0)  # V10: 1.5 for 24h, 1.2 for 7d, 1.0 otherwise
    score_narrative = Column(Text, nullable=True)      # V16.4: AI-generated executive narrative explaining score drivers
    customer = relationship("Customer", back_populates="exposures")
    actor = relationship("ThreatActor", back_populates="exposures")

class Detection(Base):
    __tablename__ = "detections"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    source = Column(String(100), nullable=False)
    ioc_type = Column(String(50), nullable=False)
    ioc_value = Column(Text, nullable=False)
    raw_text = Column(Text)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    sla_hours = Column(Integer, default=72)
    status = Column(SAEnum(DetectionStatus), default=DetectionStatus.NEW)
    matched_asset = Column(String(500))
    correlation_type = Column(String(50))   # V10: exact_domain, subdomain, ip_range, email_pattern, tech_stack, typosquat, keyword, exec_name, brand_name, cloud_asset, cidr
    source_count = Column(Integer, default=1)  # V10: how many distinct sources corroborate this IOC
    finding_id = Column(BigInteger, ForeignKey("findings.id"), nullable=True)  # V11: merged finding this detection belongs to
    confidence = Column(Float, default=0.5)
    first_seen = Column(DateTime, default=lambda: datetime.utcnow())
    last_seen = Column(DateTime, default=lambda: datetime.utcnow())
    resolved_at = Column(DateTime, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)
    match_proof = Column(JSON, default=dict)  # V16.4: S6/S7/S8 attribution proof chain
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    customer = relationship("Customer", back_populates="detections")
    finding = relationship("Finding", back_populates="detections", foreign_keys="[Detection.finding_id]")
    enrichments = relationship("Enrichment", back_populates="detection", cascade="all, delete-orphan")
    remediations = relationship("RemediationAction", back_populates="detection")
    __table_args__ = (
        Index("ix_detection_severity", "severity"), Index("ix_detection_status", "status"),
        Index("ix_detection_source", "source"), Index("ix_detection_ioc", "ioc_type", "ioc_value"),
        Index("ix_detection_created", "created_at"),
    )

class DarkWebMention(Base):
    __tablename__ = "darkweb_mentions"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    source = Column(String(100), nullable=False)
    mention_type = Column(String(50))
    title = Column(String(500))
    content_snippet = Column(Text)
    url = Column(Text)
    threat_actor = Column(String(255))
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.HIGH)
    published_at = Column(DateTime, nullable=True)
    discovered_at = Column(DateTime, default=lambda: datetime.utcnow())
    metadata_ = Column("metadata", JSON, default=dict)
    # V16.4: Dark web triage agent fields
    triage_classification = Column(String(50), nullable=True)   # pre_encryption_extortion | post_encryption_data_leak | data_auction | sector_campaign | credential_sale | likely_noise
    triage_action = Column(String(50), nullable=True)           # create_finding | notify_customer | flag_noise | escalate_ir
    triage_narrative = Column(Text, nullable=True)              # AI-generated analyst brief
    triaged_at = Column(DateTime, nullable=True)
    __table_args__ = (Index("ix_darkweb_source", "source"), Index("ix_darkweb_discovered", "discovered_at"),)

class Enrichment(Base):
    __tablename__ = "enrichments"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    detection_id = Column(BigInteger, ForeignKey("detections.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    enrichment_type = Column(String(50))
    data = Column(JSON, default=dict)
    risk_score = Column(Float, nullable=True)
    queried_at = Column(DateTime, default=lambda: datetime.utcnow())
    detection = relationship("Detection", back_populates="enrichments")

class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    detection_id = Column(BigInteger, ForeignKey("detections.id"), nullable=False)
    action_type = Column(String(50), nullable=False)
    description = Column(Text)
    assigned_to = Column(String(255))
    status = Column(String(30), default="pending")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    completed_at = Column(DateTime, nullable=True)
    detection = relationship("Detection", back_populates="remediations")

class AlertLog(Base):
    __tablename__ = "alert_log"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    detection_id = Column(BigInteger, ForeignKey("detections.id"), nullable=True)
    channel = Column(String(30), nullable=False)
    recipient = Column(String(255))
    message = Column(Text)
    sent_at = Column(DateTime, default=lambda: datetime.utcnow())
    success = Column(Boolean, default=True)
    error_detail = Column(Text, nullable=True)

class StixBundle(Base):
    __tablename__ = "stix_bundles"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    detection_id = Column(BigInteger, ForeignKey("detections.id"), nullable=True)
    bundle_json = Column(JSON, nullable=False)
    stix_version = Column(String(10), default="2.1")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())

class CollectorRun(Base):
    __tablename__ = "collector_runs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    collector_name = Column(String(100), nullable=False)
    status = Column(String(20), default="running")
    started_at = Column(DateTime, default=lambda: datetime.utcnow())
    completed_at = Column(DateTime, nullable=True)
    stats = Column(JSON, default=dict)
    error_msg = Column(Text, nullable=True)
    __table_args__ = (Index("ix_crun_name", "collector_name"), Index("ix_crun_started", "started_at"),)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user = Column(String(100), default="system")
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50))
    entity_id = Column(String(50))
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=lambda: datetime.utcnow())
    __table_args__ = (Index("ix_audit_timestamp", "timestamp"), Index("ix_audit_action", "action"),)


# ═══════════════════════════════════════════════════════════
# V11 NEW TABLES
# ═══════════════════════════════════════════════════════════

class Finding(Base):
    """The core merged intelligence record.
    
    One Finding per unique (ioc_value, ioc_type, customer_id).
    Multiple raw Detection rows -> one Finding.
    This is what analysts work with. Detections are the audit trail.
    """
    __tablename__ = "findings"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    # Identity
    ioc_value = Column(Text, nullable=False)
    ioc_type = Column(String(50), nullable=False)
    # Customer routing
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    matched_asset = Column(String(500))
    correlation_type = Column(String(50))
    # Severity + status (upgraded as sources accumulate)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    status = Column(SAEnum(DetectionStatus), default=DetectionStatus.NEW)
    sla_hours = Column(Integer, default=72)
    sla_deadline = Column(DateTime, nullable=True)
    # Multi-source tracking
    source_count = Column(Integer, default=1)
    all_sources = Column(JSON, default=list)    # ["threatfox", "otx", "paste"]
    confidence = Column(Float, default=0.5)
    # Attribution (set by attribution engine)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    actor_name = Column(String(255))            # denormalized for query speed
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)
    # Timestamps
    first_seen = Column(DateTime, default=lambda: datetime.utcnow())
    last_seen = Column(DateTime, default=lambda: datetime.utcnow())
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    updated_at = Column(DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow())

    # ── V13: AI fields ──────────────────────────────────────────────────────
    ai_severity_decision = Column(String(20), nullable=True)    # CRITICAL|HIGH|MEDIUM|LOW - Step 5a triage verdict
    ai_severity_reasoning = Column(Text, nullable=True)         # "45/72 VT engines + AbuseIPDB 91% -> CRITICAL"
    ai_severity_confidence = Column(Float, nullable=True)       # 0.0–1.0
    ai_rescore_decision = Column(String(20), nullable=True)     # Step 6.5 rescore verdict (after attribution)
    ai_rescore_reasoning = Column(Text, nullable=True)          # why rescore changed (or kept) severity
    ai_rescore_confidence = Column(Float, nullable=True)        # rescore confidence 0.0–1.0
    ai_narrative = Column(Text, nullable=True)                  # Finding-level: 2-3 sentence investigation narrative
    ai_attribution_reasoning = Column(Text, nullable=True)      # why AI picked this actor
    ai_false_positive_flag = Column(Boolean, default=False)     # AI flagged as likely FP
    ai_false_positive_reason = Column(Text, nullable=True)      # reason for FP flag
    ai_enriched_at = Column(DateTime, nullable=True)            # when AI last processed this finding
    ai_provider = Column(String(50), nullable=True)             # which provider generated AI fields
    ai_match_confidence = Column(Float, nullable=True)          # v16.4.7: AI confidence in the match (0.0-1.0)
    ai_match_reasoning = Column(Text, nullable=True)            # v16.4.7: AI explanation of match quality
    # ── Breach status ───────────────────────────────────────────────────────
    confirmed_exposure = Column(Boolean, default=False)         # True = data confirmed in attacker hands
    exposure_type = Column(String(50), nullable=True)           # ransomware_leak, stealer_log, credential_dump, data_exfiltration
    # V16.4.5: Missing from model but exist in DB
    match_proof = Column(JSON, default=dict)                    # correlation proof chain
    enrichment_narrative = Column(Text, nullable=True)          # per-finding enrichment context
    # Relationships
    customer = relationship("Customer")
    actor = relationship("ThreatActor")
    campaign = relationship("Campaign", back_populates="findings", foreign_keys="[Finding.campaign_id]")
    detections = relationship("Detection", back_populates="finding", foreign_keys="[Detection.finding_id]")
    sources = relationship("FindingSource", back_populates="finding", cascade="all, delete-orphan")
    remediations = relationship("FindingRemediation", back_populates="finding", cascade="all, delete-orphan")
    __table_args__ = (
        Index("ix_finding_ioc", "ioc_type", "ioc_value"),
        Index("ix_finding_customer", "customer_id"),
        Index("ix_finding_severity", "severity"),
        Index("ix_finding_status", "status"),
        Index("ix_finding_actor", "actor_id"),
        Index("ix_finding_created", "created_at"),
    )


class FindingSource(Base):
    """Audit trail: which raw detection sources contributed to this finding."""
    __tablename__ = "finding_sources"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    finding_id = Column(BigInteger, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    detection_id = Column(BigInteger, ForeignKey("detections.id"), nullable=False)
    source = Column(String(100), nullable=False)
    contributed_at = Column(DateTime, default=lambda: datetime.utcnow())
    finding = relationship("Finding", back_populates="sources")
    __table_args__ = (Index("ix_fsource_finding", "finding_id"),)


class Campaign(Base):
    """A coordinated attack: same actor, same customer, 3+ findings within 14 days.
    
    Kill chain stage is determined by the mix of IOC types present:
   - Recon: domain lookups, certificate transparency
   - Delivery: phishing emails, weaponized docs
   - Exploitation: CVE detections, exploit kit IOCs
   - C2: IP/domain C2 communication
   - Exfiltration: dark web credential/data leaks
    """
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    actor_name = Column(String(255))
    name = Column(String(255))                  # auto-generated: "APT28 vs Acme Corp #3"
    kill_chain_stage = Column(String(50))       # recon | delivery | exploitation | c2 | exfiltration
    finding_count = Column(Integer, default=0)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.HIGH)
    status = Column(String(30), default="active")   # active | contained | closed
    ai_narrative = Column(Text, nullable=True)       # Campaign-level: kill chain narrative (distinct from Finding.ai_narrative)
    first_seen = Column(DateTime, default=lambda: datetime.utcnow())
    last_activity = Column(DateTime, default=lambda: datetime.utcnow())
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    customer = relationship("Customer")
    actor = relationship("ThreatActor")
    findings = relationship("Finding", back_populates="campaign", foreign_keys="[Finding.campaign_id]")
    __table_args__ = (
        Index("ix_campaign_customer", "customer_id"),
        Index("ix_campaign_actor", "actor_id"),
        Index("ix_campaign_status", "status"),
    )


class ActorIoc(Base):
    """DB-driven actor -> IOC attribution map.
    Replaces hardcoded ACTOR_C2_INDICATORS dict.
    Populated by MITRE collector, OTX collector, manual import.
    """
    __tablename__ = "actor_iocs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False)
    actor_name = Column(String(255), nullable=False)    # denormalized
    ioc_type = Column(String(50), nullable=False)       # ipv4, domain, sha256, email
    ioc_value = Column(String(500), nullable=False)
    ioc_role = Column(String(50))                       # c2, dropper, exfil, phishing
    confidence = Column(Float, default=0.8)
    source = Column(String(100))                        # mitre, otx, manual
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    actor = relationship("ThreatActor")
    __table_args__ = (
        Index("ix_actor_ioc_value", "ioc_value"),
        Index("ix_actor_ioc_actor", "actor_id"),
    )


class CveProductMap(Base):
    """DB-driven CVE -> affected product map.
    Replaces hardcoded CVE_ACTOR_MAP dict for product matching.
    Populated by NVD collector from CPE data.
    """
    __tablename__ = "cve_product_map"
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), nullable=False)
    product_name = Column(String(255), nullable=False)  # "FortiOS", "Exchange", "Confluence"
    vendor = Column(String(100))
    version_range = Column(String(255))                 # "< 7.4.3"
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20))
    actively_exploited = Column(Boolean, default=False) # from CISA KEV
    source = Column(String(50), default="nvd")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    __table_args__ = (
        Index("ix_cve_product_cve", "cve_id"),
        Index("ix_cve_product_name", "product_name"),
    )


class FindingRemediation(Base):
    """Instantiated remediation action tied to a finding (not just a detection).
    Contains real values: specific IOCs to block, specific accounts to reset,
    specific systems to patch, deadline from SLA.
    """
    __tablename__ = "finding_remediations"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    finding_id = Column(BigInteger, ForeignKey("findings.id"), nullable=False)
    playbook_key = Column(String(100))
    action_type = Column(String(50), nullable=False)
    title = Column(String(500))
    # Instantiated steps with real values substituted
    steps_technical = Column(JSON, default=list)    # ["Block IP 185.234.x.x in firewall", ...]
    steps_governance = Column(JSON, default=list)
    evidence_required = Column(JSON, default=list)
    # Assignment
    assigned_to = Column(String(255))
    assigned_role = Column(String(100))
    # SLA
    deadline = Column(DateTime, nullable=True)
    sla_hours = Column(Integer)
    status = Column(String(30), default="pending")  # pending | in_progress | completed | overdue
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    finding = relationship("Finding", back_populates="remediations")
    __table_args__ = (
        Index("ix_freq_finding", "finding_id"),
        Index("ix_freq_status", "status"),
        Index("ix_freq_deadline", "deadline"),
    )


# ═══════════════════════════════════════════════════════════════════════
# V14: 3-Class IOC Model - Environmental Threat Pressure
# ═══════════════════════════════════════════════════════════════════════

class GlobalThreatActivity(Base):
    """Environmental threat pressure from unmatched IOCs.
    
    Most IOCs (Feodo C2 IPs, ThreatFox hashes, etc.) never directly match
    any customer. But they signal threat landscape pressure:
   - 50 new Feodo C2 IPs -> banking malware activity is HIGH
   - 10 new LockBit victims -> ransomware targeting healthcare is ACTIVE
    
    This converts unmatchable IOCs into sector-level risk signals.
    """
    __tablename__ = "global_threat_activity"
    id = Column(Integer, primary_key=True, autoincrement=True)
    malware_family = Column(String(255))
    category = Column(String(100), nullable=False)  # c2_botnet, ransomware, phishing, exploit_campaign, credential_theft
    targeted_sectors = Column(JSON, default=list)
    affected_products = Column(JSON, default=list)
    activity_level = Column(Float, default=0.0)     # 0.0-10.0
    ioc_count = Column(Integer, default=0)
    sources = Column(JSON, default=list)
    first_seen = Column(DateTime, default=lambda: datetime.utcnow())
    last_seen = Column(DateTime, default=lambda: datetime.utcnow())
    window_start = Column(DateTime, nullable=True)
    window_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    updated_at = Column(DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow())
    __table_args__ = (
        Index("ix_gta_category", "category"),
        Index("ix_gta_malware", "malware_family"),
    )


class ProbableExposure(Base):
    """Probable/indirect risk that doesn't require a direct IOC match.
    
    Examples:
   - Customer runs Exchange -> Exchange has had 15 critical CVEs in 24 months
      -> tech_risk_baseline even without active CVE match today
   - CVE affects "Nginx" but we don't know customer's version
      -> unknown_version exposure with lower confidence
   - Active ransomware campaign targeting healthcare + customer is healthcare
      -> sector_pressure from GlobalThreatActivity
    """
    __tablename__ = "probable_exposures"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    exposure_type = Column(String(50), nullable=False)  # tech_risk_baseline, sector_pressure, probable_cve, unknown_version
    source_detail = Column(String(500))
    product_name = Column(String(255))
    cve_id = Column(String(30))
    confidence = Column(Float, default=0.5)
    risk_points = Column(Float, default=0.0)
    last_calculated = Column(DateTime, default=lambda: datetime.utcnow())
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    customer = relationship("Customer")
    __table_args__ = (
        Index("ix_pe_customer", "customer_id"),
        Index("ix_pe_type", "exposure_type"),
    )


class ExposureHistory(Base):
    """Daily exposure score snapshots for trend charts.
    Populated by snapshot_exposure_history task (Celery beat, daily).
    Queried by GET /api/customers/{cid}/exposure-trend."""
    __tablename__ = "exposure_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    snapshot_date = Column(DateTime, nullable=False)  # UTC date of snapshot
    overall_score = Column(Float, default=0.0)
    d1_score = Column(Float, default=0.0)
    d2_score = Column(Float, default=0.0)
    d3_score = Column(Float, default=0.0)
    d4_score = Column(Float, default=0.0)
    d5_score = Column(Float, default=0.0)
    total_detections = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    __table_args__ = (
        Index("ix_eh_customer_date", "customer_id", "snapshot_date"),
    )


# ══════════════════════════════════════════════════════════════════════
# V16.4: AGENTIC AI MODELS
# ══════════════════════════════════════════════════════════════════════

class FPPattern(Base):
    """False positive memory - learns from analyst feedback.
    When analyst marks detection FP, pattern is stored here.
    Next time same pattern appears, system auto-closes or warns.
    Compounding value: system gets smarter every week.
    """
    __tablename__ = "fp_patterns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String(50), nullable=False)        # email_password_combo, ipv4, url, etc.
    ioc_value_pattern = Column(Text, nullable=False)      # exact value or regex pattern
    match_type = Column(String(20), default="exact")      # exact | prefix | cidr | regex
    source = Column(String(100), nullable=True)           # which feed produced this FP
    reason = Column(Text, nullable=True)                  # analyst reason or AI inference
    confidence = Column(Float, default=0.9)               # how confident this pattern is FP
    hit_count = Column(Integer, default=1)                # how many times this pattern matched
    last_hit_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), default="analyst")   # analyst | ai_auto | system
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    __table_args__ = (
        Index("ix_fp_customer_type", "customer_id", "ioc_type"),
    )


class SectorAdvisory(Base):
    """Cross-customer sector threat advisory - MSSP differentiator.
    Generated when same IOC hits 2+ customers in 48 hours.
    AI analyzes the pattern and produces a sector-level advisory.
    """
    __tablename__ = "sector_advisories"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_value = Column(Text, nullable=False)
    ioc_type = Column(String(50), nullable=False)
    affected_customer_count = Column(Integer, default=0)
    affected_industries = Column(JSON, default=list)       # ["healthcare", "finance"]
    affected_customer_ids = Column(JSON, default=list)     # [1, 3, 7]
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.HIGH)
    classification = Column(String(50), nullable=True)     # coordinated_campaign | shared_infra | mass_exploitation | sector_targeting
    ai_narrative = Column(Text, nullable=True)             # AI-generated sector advisory
    ai_recommended_actions = Column(JSON, default=list)    # ["Patch CVE-...", "Block IP range..."]
    status = Column(String(30), default="active")          # active | acknowledged | mitigated
    window_start = Column(DateTime, nullable=True)
    window_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    __table_args__ = (
        Index("ix_sector_adv_created", "created_at"),
    )


class ProductAlias(Base):
    """Maps vendor product name variants to a canonical name.
    Used by NVD/CVE matching to resolve 'nginx-plus' -> 'nginx', 'httpd' -> 'apache_http_server', etc.
    Pre-seeded by 06_migrate_v15.sql, extensible via API.
    """
    __tablename__ = "product_aliases"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alias = Column(String(255), nullable=False, unique=True)      # "nginx-plus", "httpd", "owa"
    canonical = Column(String(255), nullable=False)                # "nginx", "apache_http_server", "microsoft_exchange"
    vendor = Column(String(255), nullable=True)                    # "F5", "Apache", "Microsoft"


class EdrTelemetry(Base):
    """EDR/SIEM telemetry observations ingested from customer endpoints.
    Correlated against detection hashes by edr_correlator.py to produce
    confirmed-exposure findings (hash seen on customer endpoint = real breach).
    """
    __tablename__ = "edr_telemetry"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    hostname = Column(String(255), nullable=True)
    file_path = Column(String(1000), nullable=True)
    hash_sha256 = Column(String(64), nullable=True, index=True)
    hash_md5 = Column(String(32), nullable=True, index=True)
    process_name = Column(String(255), nullable=True)
    seen_at = Column(DateTime, default=lambda: datetime.utcnow())
    source = Column(String(100), default="edr_agent")             # edr_agent | siem | manual
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    __table_args__ = (
        Index("ix_edr_customer", "customer_id"),
    )
