"""
ArgusWatch Recon Engine
========================
Separate microservice with FULL internet + recon tools.
Runs REAL reconnaissance against customer domains:
 - subfinder: subdomain enumeration
 - dig/dnsx: DNS resolution (A, MX, NS, TXT, CNAME)
 - whois: domain registration data
 - nmap: port scanning (top 100 ports)
 - crt.sh: certificate transparency logs
 - httpx: HTTP probing (title, status, tech)
 - RDAP: modern WHOIS replacement
 - Reverse DNS, SPF, DMARC discovery

Auto-triggered when customer is added.
Writes directly to PostgreSQL customer_assets table.
"""

import os, asyncio, json, subprocess, logging, re
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, BackgroundTasks
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [recon] %(message)s")
log = logging.getLogger("recon")

# ── DB ──
PG = {k: os.getenv(k, d) for k, d in [
    ("POSTGRES_USER","arguswatch"),("POSTGRES_PASSWORD","arguswatch_dev_2026"),
    ("POSTGRES_HOST","postgres"),("POSTGRES_PORT","5432"),("POSTGRES_DB","arguswatch")]}
DB_URL = f"postgresql+asyncpg://{PG['POSTGRES_USER']}:{PG['POSTGRES_PASSWORD']}@{PG['POSTGRES_HOST']}:{PG['POSTGRES_PORT']}/{PG['POSTGRES_DB']}"
engine = create_async_engine(DB_URL, pool_size=5)
ASession = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ════════════════════════════════════════════════════════════
# RECON MODULES - each runs a real tool or API
# ════════════════════════════════════════════════════════════

def run_cmd(cmd, timeout=60):
    """Run a shell command and return stdout lines."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
    except Exception as e:
        log.warning(f"cmd failed [{cmd[:40]}]: {e}")
        return []

async def recon_subdomains(domain):
    """Subdomain enumeration via subfinder + crt.sh."""
    subs = set()

    # subfinder (ProjectDiscovery - passive sources)
    lines = run_cmd(f"subfinder -d {domain} -silent -timeout 20 2>/dev/null", timeout=30)
    for l in lines:
        if domain in l:
            subs.add(l.lower().strip())
    log.info(f"  subfinder: {len(lines)} subdomains for {domain}")

    # crt.sh (Certificate Transparency)
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                for cert in resp.json()[:500]:
                    cn = cert.get("common_name", "").lower().strip()
                    if cn and domain in cn and "*" not in cn:
                        subs.add(cn)
                    # Also check SAN names
                    san = cert.get("name_value", "").lower()
                    for name in san.split("\n"):
                        name = name.strip()
                        if name and domain in name and "*" not in name:
                            subs.add(name)
        log.info(f"  crt.sh: total {len(subs)} unique subdomains")
    except Exception as e:
        log.warning(f"  crt.sh failed: {e}")

    # Common subdomain brute (fast)
    common = ["www","mail","smtp","pop","imap","ftp","vpn","remote","owa","autodiscover",
              "api","dev","staging","test","beta","admin","portal","login","sso","auth",
              "cdn","static","assets","media","img","ns1","ns2","mx","mx1","mx2",
              "webmail","cpanel","whm","ssh","git","gitlab","jenkins","jira","confluence",
              "grafana","prometheus","kibana","elastic","redis","mongo","db","sql",
              "app","mobile","m","docs","wiki","help","support","status","monitor"]
    for sub in common:
        subs.add(f"{sub}.{domain}")

    return list(subs)


async def recon_dns(subdomains):
    """Resolve DNS records for all subdomains - A, AAAA, CNAME, MX, NS, TXT."""
    results = {"a_records": {}, "cname": {}, "mx": [], "ns": [], "txt": [], "alive": []}

    # Use dnsx if available for bulk resolution
    if subdomains:
        input_str = "\n".join(subdomains[:200])
        lines = run_cmd(f"echo '{input_str}' | dnsx -silent -a -resp 2>/dev/null", timeout=30)
        for l in lines:
            parts = l.split()
            if len(parts) >= 2:
                results["a_records"][parts[0]] = parts[1:]
                results["alive"].append(parts[0])

    # If dnsx didn't work, use dig via DNS-over-HTTPS
    if not results["a_records"]:
        async with httpx.AsyncClient(timeout=5) as c:
            for sub in subdomains[:50]:
                try:
                    resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={sub}&type=A",
                                      headers={"Accept": "application/dns-json"})
                    if resp.status_code == 200:
                        answers = resp.json().get("Answer", [])
                        ips = [a["data"] for a in answers if a.get("type") == 1]
                        if ips:
                            results["a_records"][sub] = ips
                            results["alive"].append(sub)
                except: pass

    # MX records for main domain
    if subdomains:
        domain = subdomains[0].split(".")[-2] + "." + subdomains[0].split(".")[-1]
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                for qtype in ["MX", "NS", "TXT"]:
                    resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type={qtype}",
                                      headers={"Accept": "application/dns-json"})
                    if resp.status_code == 200:
                        for a in resp.json().get("Answer", []):
                            val = a.get("data", "")
                            if qtype == "MX": results["mx"].append(val)
                            elif qtype == "NS": results["ns"].append(val)
                            elif qtype == "TXT": results["txt"].append(val)
        except: pass

    return results


async def recon_whois(domain):
    """Real WHOIS lookup via command line + RDAP API."""
    result = {"registrar": "", "created": "", "expires": "", "org": "", "nameservers": [], "status": []}

    # RDAP (modern WHOIS - structured JSON)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(f"https://rdap.org/domain/{domain}")
            if resp.status_code == 200:
                data = resp.json()
                result["status"] = data.get("status", [])
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        result["created"] = event.get("eventDate", "")
                    elif event.get("eventAction") == "expiration":
                        result["expires"] = event.get("eventDate", "")
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcards = entity.get("vcardArray", [None, []])
                        if vcards and len(vcards) > 1:
                            for vc in vcards[1]:
                                if isinstance(vc, list) and len(vc) > 3:
                                    if vc[0] == "fn": result["registrar"] = vc[3]
                    if "registrant" in roles:
                        vcards = entity.get("vcardArray", [None, []])
                        if vcards and len(vcards) > 1:
                            for vc in vcards[1]:
                                if isinstance(vc, list) and len(vc) > 3:
                                    if vc[0] == "org": result["org"] = vc[3]
                                    elif vc[0] == "fn" and not result["org"]: result["org"] = vc[3]
                nss = data.get("nameservers", [])
                result["nameservers"] = [ns.get("ldhName", "") for ns in nss if ns.get("ldhName")]
    except: pass

    # Fallback: whois command
    if not result["registrar"]:
        lines = run_cmd(f"whois {domain} 2>/dev/null | head -80", timeout=15)
        for l in lines:
            ll = l.lower()
            parts = l.split(":", 1)
            val = parts[1].strip() if len(parts) > 1 else ""
            if not val:
                continue
            if "registrar:" in ll: result["registrar"] = val
            elif "creation date:" in ll: result["created"] = val
            elif ("expiry date:" in ll or "expiration" in ll) and val: result["expires"] = val
            elif "registrant org" in ll: result["org"] = val

    return result


async def recon_ports(ip, top_ports=100):
    """Port scan via nmap (top ports only for speed)."""
    results = []
    lines = run_cmd(f"nmap -sT --top-ports {top_ports} -T4 --open -oG - {ip} 2>/dev/null | grep 'Ports:'", timeout=45)
    for l in lines:
        # Parse grepable format: Ports: 80/open/tcp//http///, 443/open/tcp//https///
        ports_match = re.search(r'Ports:\s*(.+)', l)
        if ports_match:
            for port_info in ports_match.group(1).split(","):
                parts = port_info.strip().split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    results.append({"port": int(parts[0]), "proto": parts[2], "service": parts[4]})
    return results


async def recon_http_probe(subdomains):
    """HTTP probe live subdomains - get title, status, tech, server headers."""
    results = []
    if not subdomains:
        return results

    # Use httpx tool if available
    input_str = "\n".join(subdomains[:100])
    lines = run_cmd(f"echo '{input_str}' | httpx -silent -status-code -title -tech-detect -server -follow-redirects 2>/dev/null", timeout=45)
    for l in lines:
        # httpx output: https://sub.domain.com [200] [Page Title] [nginx] [tech1,tech2]
        parts = l.split(" [")
        if parts:
            url = parts[0].strip()
            status = parts[1].rstrip("]") if len(parts) > 1 else ""
            title = parts[2].rstrip("]") if len(parts) > 2 else ""
            server = parts[3].rstrip("]") if len(parts) > 3 else ""
            tech = parts[4].rstrip("]") if len(parts) > 4 else ""
            results.append({"url": url, "status": status, "title": title, "server": server, "tech": tech})

    # Fallback: manual HTTP probe
    if not results:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True, verify=False) as c:
            for sub in subdomains[:30]:
                for scheme in ["https", "http"]:
                    try:
                        resp = await c.get(f"{scheme}://{sub}", timeout=5)
                        title = ""
                        title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text[:5000], re.I)
                        if title_match:
                            title = title_match.group(1).strip()[:100]
                        results.append({
                            "url": f"{scheme}://{sub}",
                            "status": str(resp.status_code),
                            "title": title,
                            "server": resp.headers.get("server", ""),
                            "tech": "",
                        })
                        break  # https worked, skip http
                    except: pass
    return results


async def recon_email_security(domain):
    """Check SPF, DMARC, DKIM records."""
    result = {"spf": "", "dmarc": "", "dkim": ""}
    async with httpx.AsyncClient(timeout=5) as c:
        # SPF
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                for a in resp.json().get("Answer", []):
                    val = a.get("data", "").strip('"')
                    if "v=spf1" in val:
                        result["spf"] = val
        except: pass
        # DMARC
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                for a in resp.json().get("Answer", []):
                    val = a.get("data", "").strip('"')
                    if "v=DMARC1" in val:
                        result["dmarc"] = val
        except: pass
    return result


# ════════════════════════════════════════════════════════════
# FULL RECON PIPELINE - chains all modules together
# ════════════════════════════════════════════════════════════

async def full_recon(customer_id: int, domain: str):
    """Run complete recon pipeline for a customer domain and write results to DB."""
    log.info(f"{'='*50}")
    log.info(f"RECON START: {domain} (customer_id={customer_id})")
    log.info(f"{'='*50}")
    started = datetime.utcnow()
    assets_created = 0
    ASSET_CAP = 200  # V16.4.7: Safety cap -  flag for review if recon finds more than this

    async def save_asset(atype, aval, crit, conf, source):
        nonlocal assets_created
        if assets_created >= ASSET_CAP:
            if assets_created == ASSET_CAP:
                log.warning(f"ASSET CAP ({ASSET_CAP}) reached for customer {customer_id} / {domain} -  skipping remaining")
            return  # Stop adding assets after cap
        async with ASession() as db:
            # Dedup
            check = await db.execute(text(
                "SELECT id FROM customer_assets WHERE customer_id=:cid AND asset_type=:t AND asset_value=:v"
            ), {"cid": customer_id, "t": atype, "v": aval})
            if check.scalar():
                return
            await db.execute(text("""
                INSERT INTO customer_assets (customer_id, asset_type, asset_value, criticality,
                    confidence, confidence_sources, discovery_source, created_at)
                VALUES (:cid, :t, :v, :crit, :conf, :csrc, :dsrc, NOW())
            """), {"cid": customer_id, "t": atype, "v": aval, "crit": crit,
                   "conf": conf, "csrc": json.dumps([source]), "dsrc": f"recon:{source}"})
            await db.commit()
            assets_created += 1

    # ── 1. Primary domain asset ──
    await save_asset("domain", domain, "critical", 1.0, "manual")
    log.info(f"  [1/8] Domain registered: {domain}")

    # ── 2. Subdomain enumeration ──
    log.info(f"  [2/8] Subdomain enumeration (subfinder + crt.sh)...")
    subdomains = await recon_subdomains(domain)
    for sub in subdomains:
        await save_asset("subdomain", sub, "high" if any(k in sub for k in ["api","admin","vpn","auth","sso","login"]) else "medium", 
                        0.8 if sub != f"www.{domain}" else 1.0, "subfinder+crtsh")
    log.info(f"  --> {len(subdomains)} subdomains found")

    # ── 3. DNS resolution ──
    log.info(f"  [3/8] DNS resolution (A, MX, NS, TXT)...")
    dns = await recon_dns(subdomains[:100])
    ips_seen = set()
    for sub, ips in dns.get("a_records", {}).items():
        for ip in ips:
            if ip not in ips_seen:
                ips_seen.add(ip)
                await save_asset("ip", ip, "high", 0.9, "dns")
    for mx in dns.get("mx", []):
        await save_asset("subdomain", mx.rstrip("."), "medium", 0.9, "dns-mx")
    for ns in dns.get("ns", []):
        await save_asset("subdomain", ns.rstrip("."), "low", 0.9, "dns-ns")
    log.info(f"  --> {len(ips_seen)} IPs, {len(dns.get('mx',[]))} MX, {len(dns.get('ns',[]))} NS")

    # ── 4. WHOIS ──
    log.info(f"  [4/8] WHOIS / RDAP lookup...")
    whois = await recon_whois(domain)
    if whois.get("org"):
        await save_asset("org_name", whois["org"], "medium", 0.85, "whois")
    if whois.get("registrar"):
        await save_asset("keyword", f"registrar:{whois['registrar']}", "low", 0.7, "whois")
    log.info(f"  --> Registrar: {whois.get('registrar','?')}, Org: {whois.get('org','?')}")

    # ── 5. Port scanning (top IPs only) ──
    scan_ips = list(ips_seen)[:5]
    if scan_ips:
        log.info(f"  [5/8] Port scan (nmap top-100 on {len(scan_ips)} IPs)...")
        for ip in scan_ips:
            ports = await recon_ports(ip, top_ports=100)
            for p in ports:
                await save_asset("tech_stack", f"{p['service']}:{p['port']}/{p['proto']}", "medium", 0.9, "nmap")
            if ports:
                log.info(f"  --> {ip}: {len(ports)} open ports ({', '.join(str(p['port']) for p in ports[:5])}...)")
    else:
        log.info(f"  [5/8] Port scan skipped (no IPs resolved)")

    # ── 6. HTTP probing ──
    alive = dns.get("alive", [])[:50]
    if alive:
        log.info(f"  [6/8] HTTP probe ({len(alive)} live hosts)...")
        http_results = await recon_http_probe(alive)
        techs_seen = set()
        for hr in http_results:
            if hr.get("server"):
                techs_seen.add(hr["server"])
            if hr.get("tech"):
                for t in hr["tech"].split(","):
                    t = t.strip()
                    if t: techs_seen.add(t)
        for tech in techs_seen:
            await save_asset("tech_stack", tech, "low", 0.7, "httpx-probe")
        log.info(f"  --> {len(http_results)} live web services, {len(techs_seen)} technologies")
    else:
        log.info(f"  [6/8] HTTP probe skipped")

    # ── 7. Email security ──
    log.info(f"  [7/8] Email security (SPF, DMARC)...")
    email_sec = await recon_email_security(domain)
    # Standard email addresses
    for prefix in ["security","admin","abuse","info","support","hr","legal","privacy","ciso","soc"]:
        await save_asset("email", f"{prefix}@{domain}", "medium", 0.6, "pattern")
    if email_sec.get("spf"):
        await save_asset("keyword", f"SPF:{email_sec['spf'][:100]}", "low", 0.9, "dns-spf")
    if email_sec.get("dmarc"):
        await save_asset("keyword", f"DMARC:{email_sec['dmarc'][:100]}", "low", 0.9, "dns-dmarc")
    log.info(f"  --> SPF: {'Yes' if email_sec.get('spf') else 'No'}, DMARC: {'Yes' if email_sec.get('dmarc') else 'No'}")

    # ── 8. Cloud & brand assets ──
    log.info(f"  [8/8] Cloud/brand/org inference...")
    # Infer cloud from DNS/HTTP
    cloud_providers = set()
    for ip in ips_seen:
        for prefix, provider in [("13.","AWS"),("52.","AWS"),("54.","AWS"),("34.","GCP"),("35.","GCP"),
                                  ("20.","Azure"),("40.","Azure"),("104.16","Cloudflare"),("172.67","Cloudflare")]:
            if ip.startswith(prefix): cloud_providers.add(provider)
    for cp in cloud_providers:
        await save_asset("cloud_asset", cp, "medium", 0.7, "ip-range-inference")
    # Brand
    await save_asset("brand_name", domain.split(".")[0].capitalize(), "medium", 0.6, "domain-inference")
    # GitHub org guess
    await save_asset("github_org", domain.split(".")[0].lower(), "low", 0.4, "guess")
    # CIDR for discovered IPs
    cidrs = set()
    for ip in ips_seen:
        parts = ip.split(".")
        if len(parts) == 4:
            cidrs.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    for cidr in cidrs:
        await save_asset("cidr", cidr, "medium", 0.6, "ip-aggregate")

    # ── Advance onboarding ──
    async with ASession() as db:
        await db.execute(text("""
            UPDATE customers SET onboarding_state='assets_added', onboarding_updated_at=NOW()
            WHERE id=:cid AND onboarding_state IN ('created', NULL)
        """), {"cid": customer_id})
        await db.commit()

    elapsed = (datetime.utcnow() - started).total_seconds()
    log.info(f"{'='*50}")
    log.info(f"RECON COMPLETE: {domain}")
    log.info(f"  {assets_created} assets discovered in {elapsed:.1f}s")
    log.info(f"  Subdomains: {len(subdomains)}, IPs: {len(ips_seen)}, Techs: {len(cloud_providers)}")
    log.info(f"{'='*50}")

    return {
        "domain": domain, "customer_id": customer_id,
        "assets_created": assets_created,
        "subdomains": len(subdomains), "ips": len(ips_seen),
        "whois": whois, "email_security": email_sec,
        "elapsed_seconds": round(elapsed, 1),
    }


# ════════════════════════════════════════════════════════════
# FASTAPI APP
# ════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Recon Engine ready - waiting for targets")
    # Wait for DB
    for attempt in range(10):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            break
        except:
            await asyncio.sleep(3)
    yield

app = FastAPI(title="ArgusWatch Recon Engine", lifespan=lifespan)

@app.get("/health")
async def health():
    # Check which tools are available
    tools = {}
    for tool in ["subfinder", "nmap", "whois", "dig", "dnsx"]:
        r = subprocess.run(f"which {tool}", shell=True, capture_output=True)
        tools[tool] = r.returncode == 0
    # Check httpx tool (not Python httpx)
    r = subprocess.run("httpx -version 2>/dev/null || echo missing", shell=True, capture_output=True, text=True)
    tools["httpx-toolkit"] = "missing" not in r.stdout
    return {"status": "ok", "tools": tools}

@app.post("/recon/{customer_id}")
async def trigger_recon(customer_id: int, domain: str = None, background_tasks: BackgroundTasks = None):
    """Full recon pipeline for a customer. Auto-detects domain from DB if not provided."""
    # Auto-detect domain from customer
    if not domain:
        async with ASession() as db:
            r = await db.execute(text("""
                SELECT c.name, c.email,
                    (SELECT asset_value FROM customer_assets WHERE customer_id=c.id AND asset_type='domain' LIMIT 1)
                FROM customers c WHERE c.id=:cid
            """), {"cid": customer_id})
            row = r.first()
            if not row:
                return {"error": f"Customer {customer_id} not found"}
            name, email, existing_domain = row
            if existing_domain:
                domain = existing_domain
            elif email and "@" in email:
                domain = email.split("@")[1]
            else:
                # Infer from name
                domain_map = {"paypal":"paypal.com","amazon":"amazon.com","google":"google.com",
                    "microsoft":"microsoft.com","apple":"apple.com","meta":"meta.com",
                    "netflix":"netflix.com","solvent":"solventcyber.com"}
                nl = name.lower().split()[0] if name else ""
                domain = domain_map.get(nl, f"{nl}.com")

    if background_tasks:
        background_tasks.add_task(full_recon, customer_id, domain)
        return {"status": "started", "domain": domain, "customer_id": customer_id,
                "message": f"Recon running in background for {domain}"}
    else:
        return await full_recon(customer_id, domain)

@app.get("/recon/quick/{domain}")
async def quick_recon(domain: str):
    """Quick domain recon without saving to DB - returns results directly."""
    result = {"domain": domain}
    result["subdomains"] = await recon_subdomains(domain)
    result["dns"] = await recon_dns(result["subdomains"][:30])
    result["whois"] = await recon_whois(domain)
    result["email_security"] = await recon_email_security(domain)
    return result
