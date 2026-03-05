"""
Demo Data Seeder v2 — Consistent, Traceable, Non-Fake
======================================================
RULES:
  1. ZERO randomness — every customer gets SPECIFIC intel tied to their domain
  2. Detections and Findings share the SAME customer_id + ioc_value (no mismatch)
  3. ExposureHistory is populated so D1-D5 scores are REAL, not fallback formula
  4. Coverage categories match the assets+detections (no zero-coverage-with-high-score)
  5. Every number is EXPLAINABLE — traceable from source to score
"""
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("arguswatch.seed.demo")

CUSTOMERS = [
    {
        "name": "Yahoo", "industry": "technology", "tier": "enterprise",
        "email": "security@yahoo.com", "domain": "yahoo.com",
        "assets": [
            ("domain", "yahoo.com", "critical"),
            ("email_domain", "yahoo.com", "critical"),
            ("subdomain", "mail.yahoo.com", "high"),
            ("subdomain", "api.yahoo.com", "high"),
            ("brand_name", "Yahoo", "critical"),
            ("keyword", "yahoo", "critical"),
            ("ip", "98.137.11.163", "high"),
            ("tech_stack", "Apache", "medium"),
        ],
        "detections": [
            ("hudsonrock", "email_password_combo", "admin@yahoo.com:W3lc0m3!2024", "CRITICAL",
             "HudsonRock stealer log — admin credential for yahoo.com from Raccoon infostealer dump", 4),
            ("hudsonrock", "email_password_combo", "hr.admin@yahoo.com:P@ssw0rd123", "HIGH",
             "HudsonRock stealer log — HR admin credential from Vidar stealer", 12),
            ("threatfox", "domain", "yahoo-security-update.com", "HIGH",
             "ThreatFox: Typosquat domain mimicking Yahoo security portal", 12),
            ("cisa_kev", "cve_id", "CVE-2024-21887", "CRITICAL",
             "Ivanti Connect Secure command injection — Yahoo runs Ivanti VPN per tech_stack", 4),
            ("openphish", "url", "https://yahoo-verify-account.net/login", "HIGH",
             "OpenPhish: Active phishing page targeting Yahoo credentials", 12),
            ("abuse_ch", "ipv4", "185.215.113.97", "MEDIUM",
             "AbuseIPDB: Emotet C2 scanning yahoo.com mail servers", 72),
            ("paste", "email", "ciso@yahoo.com", "MEDIUM",
             "Credential found on pastebin.com in combo list dated 2025-12", 72),
            ("nvd", "cve_id", "CVE-2024-3400", "CRITICAL",
             "PAN-OS GlobalProtect command injection — Yahoo uses Palo Alto firewalls", 4),
        ],
    },
    {
        "name": "Shopify", "industry": "technology", "tier": "premium",
        "email": "security@shopify.com", "domain": "shopify.com",
        "assets": [
            ("domain", "shopify.com", "critical"),
            ("email_domain", "shopify.com", "critical"),
            ("subdomain", "api.shopify.com", "critical"),
            ("subdomain", "partners.shopify.com", "high"),
            ("brand_name", "Shopify", "critical"),
            ("keyword", "shopify", "critical"),
            ("github_org", "Shopify", "high"),
            ("tech_stack", "Ruby on Rails", "medium"),
            ("tech_stack", "MySQL", "medium"),
        ],
        "detections": [
            ("threatfox", "url", "https://shopify-partner-login.xyz/auth", "CRITICAL",
             "ThreatFox: Phishing page targeting Shopify partner credentials", 4),
            ("hudsonrock", "email_password_combo", "dev@shopify.com:gh_token2024", "HIGH",
             "HudsonRock stealer log — developer credential with GitHub token reference", 12),
            ("malwarebazaar", "hash_sha256", "a3f2b8c91d4e67f0123456789abcdef0123456789abcdef0123456789abcdef0", "MEDIUM",
             "MalwareBazaar: Shopify-themed credential harvester binary", 72),
            ("nvd", "cve_id", "CVE-2025-0282", "HIGH",
             "Ivanti Connect Secure buffer overflow — Shopify partner VPN", 12),
            ("openphish", "url", "https://shopify-billing-verify.com/update", "HIGH",
             "OpenPhish: Fake Shopify billing page for merchant credential theft", 12),
            ("paste", "email", "engineering@shopify.com", "MEDIUM",
             "Engineering team email in scraped LinkedIn combo list", 72),
        ],
    },
    {
        "name": "VulnWeb Demo", "industry": "technology", "tier": "standard",
        "email": "admin@vulnweb.com", "domain": "vulnweb.com",
        "assets": [
            ("domain", "vulnweb.com", "critical"),
            ("email_domain", "vulnweb.com", "critical"),
            ("subdomain", "testphp.vulnweb.com", "high"),
            ("brand_name", "VulnWeb", "medium"),
            ("keyword", "vulnweb", "medium"),
            ("ip", "44.228.249.3", "high"),
            ("tech_stack", "PHP", "medium"),
            ("tech_stack", "Apache", "medium"),
        ],
        "detections": [
            ("abuse_ch", "ipv4", "44.228.249.3", "HIGH",
             "AbuseIPDB: VulnWeb server IP flagged — active SQL injection scanning target", 12),
            ("threatfox", "url", "http://testphp.vulnweb.com/listproducts.php?cat=1", "MEDIUM",
             "ThreatFox: Known vulnerable endpoint referenced in exploit kit config", 72),
            ("nvd", "cve_id", "CVE-2024-47575", "CRITICAL",
             "FortiManager missing authentication — VulnWeb demo infrastructure exposed", 4),
            ("paste", "email", "admin@vulnweb.com", "MEDIUM",
             "Admin email in credential dump from third-party breach", 72),
        ],
    },
    {
        "name": "Uber", "industry": "transportation", "tier": "enterprise",
        "email": "security@uber.com", "domain": "uber.com",
        "assets": [
            ("domain", "uber.com", "critical"),
            ("email_domain", "uber.com", "critical"),
            ("subdomain", "auth.uber.com", "critical"),
            ("subdomain", "api.uber.com", "critical"),
            ("subdomain", "driver.uber.com", "high"),
            ("brand_name", "Uber", "critical"),
            ("keyword", "uber", "critical"),
            ("github_org", "uber", "high"),
            ("tech_stack", "Go", "medium"),
            ("tech_stack", "Java", "medium"),
            ("aws_account", "uber-prod", "critical"),
        ],
        "detections": [
            ("hudsonrock", "email_password_combo", "ops@uber.com:Ub3rS3cur3!!", "CRITICAL",
             "HudsonRock stealer log — ops credential from LummaC2 stealer campaign", 4),
            ("hudsonrock", "email_password_combo", "driver-support@uber.com:D5upport2024", "HIGH",
             "HudsonRock stealer log — driver support portal credential", 12),
            ("threatfox", "domain", "uber-driver-verify.com", "HIGH",
             "ThreatFox: Typosquat targeting Uber driver onboarding", 12),
            ("cisa_kev", "cve_id", "CVE-2024-21887", "CRITICAL",
             "Ivanti Connect Secure command injection — Uber corporate VPN", 4),
            ("feodo", "ipv4", "34.204.119.63", "CRITICAL",
             "Feodo C2: Dridex banking trojan — infrastructure overlaps with Uber IP range", 4),
            ("openphish", "url", "https://uber-account-security.net/verify", "HIGH",
             "OpenPhish: Credential phishing targeting Uber employees", 12),
            ("ransomfeed", "domain", "uber.com", "CRITICAL",
             "RansomFeed: Uber mentioned in ALPHV/BlackCat leak site negotiation page", 4),
            ("malwarebazaar", "hash_sha256", "b4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890abcde", "HIGH",
             "MalwareBazaar: Cobalt Strike beacon configured with uber.com callback", 12),
            ("nvd", "cve_id", "CVE-2024-3400", "CRITICAL",
             "PAN-OS GlobalProtect OS command injection — Uber runs PAN-OS firewalls", 4),
            ("abuse_ch", "ipv4", "89.248.167.131", "MEDIUM",
             "AbuseIPDB: Mass credential brute-force scanner targeting uber.com", 72),
        ],
    },
    {
        "name": "Starbucks", "industry": "retail", "tier": "premium",
        "email": "security@starbucks.com", "domain": "starbucks.com",
        "assets": [
            ("domain", "starbucks.com", "critical"),
            ("email_domain", "starbucks.com", "critical"),
            ("subdomain", "app.starbucks.com", "critical"),
            ("subdomain", "rewards.starbucks.com", "high"),
            ("brand_name", "Starbucks", "critical"),
            ("keyword", "starbucks", "critical"),
            ("tech_stack", "Oracle", "medium"),
            ("ip", "23.196.52.6", "medium"),
        ],
        "detections": [
            ("hudsonrock", "email_password_combo", "rewards-admin@starbucks.com:Rew4rds!2024", "CRITICAL",
             "HudsonRock stealer log — rewards admin credential from RedLine stealer", 4),
            ("openphish", "url", "https://starbucks-rewards-verify.com/claim", "HIGH",
             "OpenPhish: Fake rewards page harvesting Starbucks customer credentials", 12),
            ("threatfox", "domain", "starbucks-giftcard-claim.com", "HIGH",
             "ThreatFox: Typosquat targeting Starbucks gift card users", 12),
            ("paste", "email", "store-ops@starbucks.com", "MEDIUM",
             "Store operations email in credential combo list", 72),
            ("nvd", "cve_id", "CVE-2024-47575", "HIGH",
             "FortiManager missing auth — Starbucks retail POS network management", 12),
            ("abuse_ch", "ipv4", "94.232.249.211", "MEDIUM",
             "AbuseIPDB: TrickBot C2 scanning Starbucks payment processing IPs", 72),
            ("ransomfeed", "domain", "starbucks.com", "HIGH",
             "RansomFeed: Starbucks brand mentioned in LockBit affiliate claims (unconfirmed)", 12),
        ],
    },
    {
        "name": "GitHub", "industry": "technology", "tier": "enterprise",
        "email": "security@github.com", "domain": "github.com",
        "assets": [
            ("domain", "github.com", "critical"),
            ("email_domain", "github.com", "critical"),
            ("subdomain", "api.github.com", "critical"),
            ("subdomain", "gist.github.com", "high"),
            ("subdomain", "raw.githubusercontent.com", "high"),
            ("brand_name", "GitHub", "critical"),
            ("keyword", "github", "critical"),
            ("github_org", "github", "critical"),
            ("tech_stack", "Ruby on Rails", "medium"),
            ("tech_stack", "Go", "medium"),
            ("tech_stack", "MySQL", "medium"),
            ("aws_account", "github-prod", "critical"),
        ],
        "detections": [
            ("hudsonrock", "email_password_combo", "admin@github.com:Gh!tAdm1n2024", "CRITICAL",
             "HudsonRock stealer log — admin credential from Raccoon infostealer V2", 4),
            ("hudsonrock", "email_password_combo", "security@github.com:S3cur1ty#2025", "CRITICAL",
             "HudsonRock stealer log — security team credential from LummaC2 stealer", 4),
            ("threatfox", "domain", "github-oauth-verify.com", "HIGH",
             "ThreatFox: Typosquat domain for OAuth token phishing targeting GitHub devs", 12),
            ("threatfox", "url", "https://github-security-alert.net/2fa-reset", "HIGH",
             "ThreatFox: Phishing page mimicking GitHub 2FA reset flow", 12),
            ("cisa_kev", "cve_id", "CVE-2024-21887", "CRITICAL",
             "Ivanti Connect Secure command injection — GitHub enterprise VPN", 4),
            ("malwarebazaar", "hash_sha256", "c5d6e7f8901234567890abcdef1234567890abcdef1234567890abcdef123456", "HIGH",
             "MalwareBazaar: PyPI supply chain malware exfiltrating to github-cdn.evil.com", 12),
            ("openphish", "url", "https://github-auth-security.com/verify", "HIGH",
             "OpenPhish: Active credential harvesting page mimicking GitHub login", 12),
            ("nvd", "cve_id", "CVE-2025-0282", "HIGH",
             "Ivanti Connect Secure buffer overflow — GitHub Corp VPN", 12),
            ("abuse_ch", "ipv4", "45.155.205.233", "MEDIUM",
             "AbuseIPDB: QakBot C2 hosting fake GitHub release pages", 72),
            ("paste", "email", "ops@github.com", "MEDIUM",
             "Operations email in combo list from third-party SaaS breach", 72),
            ("nvd", "cve_id", "CVE-2024-3400", "CRITICAL",
             "PAN-OS GlobalProtect command injection — GitHub network edge firewalls", 4),
            ("feodo", "ipv4", "185.215.113.97", "HIGH",
             "Feodo C2: Emotet distribution node observed scanning github.com", 12),
        ],
    },
]

ACTORS = [
    {"name": "APT28", "mitre_id": "G0007", "aliases": ["Fancy Bear", "Sofacy"],
     "origin_country": "Russia", "motivation": "Espionage", "sophistication": "Expert",
     "active_since": "2004", "target_sectors": ["Government", "Military", "Technology", "Aerospace"],
     "techniques": ["T1566.001", "T1059.001", "T1078", "T1071.001", "T1048", "T1003.001"],
     "description": "APT28 is attributed to Russia's GRU Unit 26165."},
    {"name": "APT29", "mitre_id": "G0016", "aliases": ["Cozy Bear", "The Dukes"],
     "origin_country": "Russia", "motivation": "Espionage", "sophistication": "Expert",
     "active_since": "2008", "target_sectors": ["Government", "Technology", "Healthcare"],
     "techniques": ["T1195.002", "T1078", "T1098", "T1059.001", "T1071.001", "T1027"],
     "description": "APT29 is attributed to Russia's SVR, known for SolarWinds."},
    {"name": "Lazarus Group", "mitre_id": "G0032", "aliases": ["Hidden Cobra", "Zinc"],
     "origin_country": "North Korea", "motivation": "Financial", "sophistication": "Expert",
     "active_since": "2009", "target_sectors": ["Financial", "Technology", "Cryptocurrency"],
     "techniques": ["T1566.001", "T1059.007", "T1195.002", "T1071.001", "T1486"],
     "description": "Lazarus is a North Korean state group responsible for WannaCry."},
    {"name": "LockBit", "mitre_id": "S0832", "aliases": ["LockBit 3.0", "LockBit Black"],
     "origin_country": "Russia", "motivation": "Financial", "sophistication": "Advanced",
     "active_since": "2019", "target_sectors": ["Healthcare", "Retail", "Manufacturing"],
     "techniques": ["T1486", "T1490", "T1027", "T1059.001", "T1548.002"],
     "description": "LockBit is one of the most active ransomware-as-a-service operations."},
    {"name": "ALPHV", "mitre_id": "S1038", "aliases": ["BlackCat", "Noberus"],
     "origin_country": "Russia", "motivation": "Financial", "sophistication": "Advanced",
     "active_since": "2021", "target_sectors": ["Transportation", "Technology", "Healthcare", "Retail"],
     "techniques": ["T1486", "T1490", "T1059.001", "T1071.001", "T1078", "T1048"],
     "description": "ALPHV/BlackCat ransomware, known for double-extortion attacks."},
    {"name": "APT1", "mitre_id": "G0006", "aliases": ["Comment Crew", "Shanghai Group"],
     "origin_country": "China", "motivation": "Espionage", "sophistication": "Expert",
     "active_since": "2006", "target_sectors": ["Technology", "Aerospace", "Energy"],
     "techniques": ["T1190", "T1059.001", "T1543.003", "T1071.001", "T1048", "T1078"],
     "description": "APT1 is attributed to PLA Unit 61398."},
]


def calculate_d1_d5(customer_data):
    """Calculate real D1-D5 scores from the customer's actual detections.
    
    D1: Finding Severity (0-25) — weighted count of CRITICAL/HIGH/MEDIUM/LOW
    D2: Source Diversity (0-20) — how many distinct sources found threats
    D3: Sector Exposure (0-15) — industry-specific risk premium
    D4: Recency (0-20) — how recent are the threats (more CRITICAL = more active)
    D5: Credential Exposure (0-20) — stealer logs, credential dumps
    
    Overall = D1 + D2 + D3 + D4 + D5 (0-100)
    """
    dets = customer_data["detections"]
    sev_weights = {"CRITICAL": 6, "HIGH": 3, "MEDIUM": 1, "LOW": 0.5}
    
    # D1: Severity-weighted
    d1_raw = sum(sev_weights.get(d[3], 1) for d in dets)
    d1 = round(min(25, d1_raw), 1)

    # D2: Source diversity
    sources = set(d[0] for d in dets)
    d2 = round(min(20, len(sources) * 3.5), 1)

    # D3: Sector risk
    sector_risk = {"technology": 8, "financial": 12, "healthcare": 11,
                   "retail": 9, "transportation": 7, "government": 13, "energy": 10}
    d3 = round(sector_risk.get(customer_data.get("industry", ""), 5), 1)

    # D4: Recency
    crit_count = sum(1 for d in dets if d[3] == "CRITICAL")
    d4 = round(min(20, crit_count * 5 + len(dets) * 0.8), 1)

    # D5: Credential exposure
    cred_types = {"email_password_combo", "email"}
    cred_count = sum(1 for d in dets if d[1] in cred_types)
    d5 = round(min(20, cred_count * 7), 1)

    overall = round(min(100, d1 + d2 + d3 + d4 + d5), 1)

    return {
        "d1": d1, "d2": d2, "d3": d3, "d4": d4, "d5": d5,
        "overall": overall,
        "explanation": {
            "d1": f"{len(dets)} findings, severity sum={d1_raw:.0f}, D1={d1}/25",
            "d2": f"{len(sources)} sources ({', '.join(sorted(sources))}), D2={d2}/20",
            "d3": f"industry={customer_data.get('industry','?')}, D3={d3}/15",
            "d4": f"{crit_count} CRITICAL, {len(dets)} total, D4={d4}/20",
            "d5": f"{cred_count} credential IOCs, D5={d5}/20",
        },
    }


async def seed_demo_data():
    """Seed all tables with consistent, traceable demo data."""
    from arguswatch.database import async_session
    from arguswatch.models import (
        CollectorRun, Detection, SeverityLevel, DetectionStatus,
        ThreatActor, DarkWebMention, Finding, FindingSource,
        Customer, CustomerAsset, AssetType, CustomerExposure,
        ExposureHistory,
    )
    from sqlalchemy import select, func as sqlfunc

    now = datetime.utcnow()
    sevmap = {"CRITICAL": SeverityLevel.CRITICAL, "HIGH": SeverityLevel.HIGH,
              "MEDIUM": SeverityLevel.MEDIUM, "LOW": SeverityLevel.LOW}
    result = {"status": "seeded", "version": "v2-consistent"}

    # ═══ STEP 1: COLLECTOR RUNS ═══
    try:
        async with async_session() as db:
            rc = (await db.execute(select(sqlfunc.count(CollectorRun.id)))).scalar() or 0
            if rc < 10:
                sources = ["cisa_kev", "threatfox", "feodo", "malwarebazaar", "abuse_ch",
                           "openphish", "ransomfeed", "nvd", "rss", "paste", "hudsonrock", "mitre"]
                for src in sources:
                    for offset_h in [0, 2, 5]:
                        t = now - timedelta(hours=offset_h, minutes=15)
                        db.add(CollectorRun(
                            collector_name=src, status="completed",
                            started_at=t - timedelta(seconds=12), completed_at=t,
                            stats={"new": 3 + offset_h, "skipped": offset_h * 2},
                        ))
                await db.commit()
                result["collectors"] = len(sources)
    except Exception as e:
        logger.warning(f"Seed collectors: {e}")

    # ═══ STEP 2: THREAT ACTORS ═══
    actor_ids = {}
    try:
        async with async_session() as db:
            for a in ACTORS:
                existing = await db.execute(select(ThreatActor).where(ThreatActor.name == a["name"]))
                actor = existing.scalar_one_or_none()
                if actor:
                    actor_ids[a["name"]] = actor.id
                    continue
                ta = ThreatActor(
                    name=a["name"], mitre_id=a.get("mitre_id"), aliases=a.get("aliases", []),
                    origin_country=a.get("origin_country"), motivation=a.get("motivation"),
                    sophistication=a.get("sophistication"), active_since=a.get("active_since"),
                    target_sectors=a.get("target_sectors", []), techniques=a.get("techniques", []),
                    description=a.get("description", ""), source="mitre",
                )
                db.add(ta); await db.flush()
                actor_ids[a["name"]] = ta.id
            await db.commit()
        result["actors"] = len(actor_ids)
    except Exception as e:
        logger.warning(f"Seed actors: {e}")

    # ═══ STEP 3: CUSTOMERS + ASSETS + DETECTIONS + FINDINGS (ALL CONSISTENT) ═══
    sector_actors = {
        "technology": ["APT29", "APT1", "Lazarus Group"],
        "transportation": ["ALPHV", "APT28"],
        "retail": ["LockBit", "Lazarus Group"],
    }
    asset_map = {
        "domain": AssetType.DOMAIN, "email_domain": AssetType.EMAIL_DOMAIN,
        "subdomain": AssetType.SUBDOMAIN, "ip": AssetType.IP,
        "brand_name": AssetType.BRAND_NAME, "keyword": AssetType.KEYWORD,
        "github_org": AssetType.GITHUB_ORG, "tech_stack": AssetType.TECH_STACK,
        "aws_account": AssetType.AWS_ACCOUNT, "cidr": AssetType.CIDR,
        "azure_tenant": AssetType.AZURE_TENANT, "org_name": AssetType.ORG_NAME,
    }

    for cust_data in CUSTOMERS:
        try:
            async with async_session() as db:
                # --- Customer ---
                existing = await db.execute(select(Customer).where(Customer.name == cust_data["name"]))
                customer = existing.scalar_one_or_none()
                if not customer:
                    customer = Customer(
                        name=cust_data["name"], industry=cust_data["industry"],
                        tier=cust_data["tier"], email=cust_data["email"],
                        onboarding_state="monitoring", active=True,
                    )
                    db.add(customer); await db.flush()
                cid = customer.id

                # --- Assets ---
                for atype_str, aval, crit in cust_data.get("assets", []):
                    atype = asset_map.get(atype_str)
                    if not atype:
                        continue
                    ea = await db.execute(select(CustomerAsset).where(
                        CustomerAsset.customer_id == cid, CustomerAsset.asset_value == aval))
                    if ea.scalar_one_or_none():
                        continue
                    db.add(CustomerAsset(
                        customer_id=cid, asset_type=atype, asset_value=aval,
                        criticality=crit, confidence=0.95,
                        confidence_sources=["consistent_seed_v2"],
                        discovery_source="seed_v2",
                    ))

                # --- Detections + Findings (SAME customer, SAME IOC, linked) ---
                actors_for_sector = sector_actors.get(cust_data["industry"], ["APT28"])
                for i, (src, itype, ival, sev_str, raw_text, sla) in enumerate(cust_data["detections"]):
                    d = Detection(
                        customer_id=cid, source=src, ioc_type=itype, ioc_value=ival,
                        raw_text=raw_text, severity=sevmap[sev_str], sla_hours=sla,
                        status=DetectionStatus.NEW, confidence=0.85,
                        source_count=1, matched_asset=cust_data["domain"],
                        correlation_type="exact_domain",
                        created_at=now - timedelta(hours=i * 3),
                        first_seen=now - timedelta(hours=i * 3 + 1),
                        last_seen=now - timedelta(hours=max(0, i - 1)),
                    )
                    db.add(d); await db.flush()

                    actor_name = actors_for_sector[i % len(actors_for_sector)]
                    aid = actor_ids.get(actor_name)
                    f = Finding(
                        ioc_value=ival, ioc_type=itype, customer_id=cid,
                        severity=sevmap[sev_str], status=DetectionStatus.NEW,
                        sla_hours=sla, sla_deadline=now + timedelta(hours=sla),
                        source_count=1, all_sources=[src],
                        confidence=0.85, matched_asset=cust_data["domain"],
                        correlation_type="exact_domain",
                        actor_id=aid, actor_name=actor_name,
                        first_seen=now - timedelta(hours=i * 3 + 1),
                        last_seen=now - timedelta(hours=max(0, i - 1)),
                        created_at=now - timedelta(hours=i * 3),
                        ai_narrative=raw_text,
                        ai_severity_decision=sev_str,
                        ai_severity_confidence=0.88,
                    )
                    db.add(f); await db.flush()
                    d.finding_id = f.id
                    db.add(FindingSource(
                        finding_id=f.id, detection_id=d.id, source=src,
                        contributed_at=now - timedelta(hours=i * 3),
                    ))

                # --- D1-D5 Exposure History (from REAL detection data) ---
                scores = calculate_d1_d5(cust_data)
                db.add(ExposureHistory(
                    customer_id=cid, snapshot_date=now,
                    overall_score=scores["overall"],
                    d1_score=scores["d1"], d2_score=scores["d2"],
                    d3_score=scores["d3"], d4_score=scores["d4"],
                    d5_score=scores["d5"],
                    total_detections=len(cust_data["detections"]),
                    critical_count=sum(1 for d in cust_data["detections"] if d[3] == "CRITICAL"),
                ))
                # Trend history (7 days)
                for days_ago in [1, 2, 3, 5, 7]:
                    drift = days_ago * 1.5
                    db.add(ExposureHistory(
                        customer_id=cid,
                        snapshot_date=now - timedelta(days=days_ago),
                        overall_score=max(0, scores["overall"] - drift),
                        d1_score=max(0, scores["d1"] - drift * 0.3),
                        d2_score=scores["d2"],
                        d3_score=scores["d3"],
                        d4_score=max(0, scores["d4"] - drift * 0.2),
                        d5_score=max(0, scores["d5"] - drift * 0.1),
                        total_detections=max(0, len(cust_data["detections"]) - days_ago),
                        critical_count=max(0, sum(1 for dd in cust_data["detections"] if dd[3] == "CRITICAL") - (1 if days_ago > 3 else 0)),
                    ))

                # --- CustomerExposure per actor ---
                for actor_name in actors_for_sector:
                    aid = actor_ids.get(actor_name)
                    if not aid:
                        continue
                    actor_info = next((a for a in ACTORS if a["name"] == actor_name), {})
                    sector_match = cust_data["industry"].capitalize() in actor_info.get("target_sectors", [])
                    db.add(CustomerExposure(
                        customer_id=cid, actor_id=aid,
                        exposure_score=round(scores["overall"] / len(actors_for_sector), 1),
                        sector_match=sector_match,
                        detection_count=len(cust_data["detections"]) // len(actors_for_sector),
                        darkweb_mentions=1 if any(d[0] == "ransomfeed" for d in cust_data["detections"]) else 0,
                        factor_breakdown={"d1": scores["d1"], "d2": scores["d2"], "d3": scores["d3"],
                                          "d4": scores["d4"], "d5": scores["d5"],
                                          "explanation": scores["explanation"]},
                    ))

                await db.commit()
                logger.info(f"  Seeded {cust_data['name']}: {len(cust_data['detections'])} det+find, score={scores['overall']}")
                result[cust_data["name"]] = {
                    "detections": len(cust_data["detections"]),
                    "findings": len(cust_data["detections"]),
                    "assets": len(cust_data.get("assets", [])),
                    "exposure_score": scores["overall"],
                    "d1": scores["d1"], "d2": scores["d2"], "d3": scores["d3"],
                    "d4": scores["d4"], "d5": scores["d5"],
                }
        except Exception as e:
            logger.warning(f"Seed {cust_data['name']}: {e}")
            result[f"{cust_data['name']}_error"] = str(e)

    # ═══ STEP 4: DARK WEB MENTIONS (tied to specific customers) ═══
    darkweb_items = [
        ("Uber", "ransomfeed", "ransomware_claim", "ALPHV claims Uber data",
         "Alleged exfiltration of driver PII and payment data.", "ALPHV", SeverityLevel.CRITICAL),
        ("Starbucks", "ransomfeed", "data_auction", "LockBit: Starbucks POS data",
         "Claims point-of-sale transaction data.", "LockBit", SeverityLevel.HIGH),
        ("GitHub", "paste", "credential_dump", "GitHub employee credentials",
         "20+ github.com email/password combos on pastebin.", None, SeverityLevel.HIGH),
        ("Yahoo", "paste", "credential_dump", "Yahoo admin credentials in stealer log",
         "admin@yahoo.com with session tokens from Raccoon.", None, SeverityLevel.CRITICAL),
        ("Shopify", "rss", "phishing_campaign", "Shopify partner phishing wave",
         "Multiple domains mimicking Shopify partner portal.", None, SeverityLevel.HIGH),
    ]
    try:
        async with async_session() as db:
            cr = await db.execute(select(Customer))
            cust_map = {c.name: c.id for c in cr.scalars().all()}
            for cname, src, mtype, title, content, actor, sev in darkweb_items:
                cid = cust_map.get(cname)
                if not cid:
                    continue
                db.add(DarkWebMention(
                    customer_id=cid, source=src, mention_type=mtype,
                    title=title, content_snippet=content,
                    threat_actor=actor, severity=sev,
                    published_at=now - timedelta(hours=6),
                    discovered_at=now - timedelta(hours=2),
                ))
            await db.commit()
            result["darkweb"] = len(darkweb_items)
    except Exception as e:
        logger.warning(f"Seed darkweb: {e}")

    return result
