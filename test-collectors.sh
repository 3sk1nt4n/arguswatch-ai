#!/bin/bash
# ══════════════════════════════════════════════════════════════
# ArgusWatch v16.4.3  -  Collector Verification Script
# ══════════════════════════════════════════════════════════════
# Run AFTER: docker compose up -d --build
# Wait until: docker ps shows all containers healthy
#
# This script tests the 3 new collectors (GitHub Gist, Sourcegraph,
# Alt Paste) and the 100 IOC pattern_matcher. No fake data.
# Every result comes from real APIs or real Docker containers.
# ══════════════════════════════════════════════════════════════

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ArgusWatch v16.4.3  -  Collector Verification"
echo "══════════════════════════════════════════════════════════════"
echo ""

PASS=0; FAIL=0; WARN=0

pass() { echo -e "  ${GREEN}✅ PASS${NC}: $1"; ((PASS++)); }
fail() { echo -e "  ${RED}❌ FAIL${NC}: $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}⚠️  WARN${NC}: $1"; ((WARN++)); }
info() { echo -e "  ${CYAN}ℹ️  INFO${NC}: $1"; }

# ─── PRE-CHECK: Are containers running? ───
echo -e "${BOLD}TEST 0: Docker containers${NC}"
echo "────────────────────────────────────────"

for svc in arguswatch-backend arguswatch-intel-proxy arguswatch-postgres; do
    if docker ps --format '{{.Names}}' | grep -q "$svc"; then
        pass "$svc is running"
    else
        fail "$svc is NOT running  -  run: docker compose up -d --build"
    fi
done
echo ""

# ─── TEST 1: GitHub Gist API ───
echo -e "${BOLD}TEST 1: GitHub Gist API (feeds ~40 IOC types)${NC}"
echo "────────────────────────────────────────"

GIST_RESP=$(curl -sf "https://api.github.com/gists/public?per_page=3" 2>/dev/null || echo "CURL_FAILED")

if [ "$GIST_RESP" = "CURL_FAILED" ]; then
    fail "Cannot reach api.github.com  -  check internet"
else
    GIST_COUNT=$(echo "$GIST_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "0")
    if [ "$GIST_COUNT" -gt "0" ]; then
        pass "GitHub Gist API responds  -  got $GIST_COUNT gists"
        
        # Check if content is inline
        HAS_CONTENT=$(echo "$GIST_RESP" | python3 -c "
import json,sys
gists=json.load(sys.stdin)
for g in gists:
    for f in g.get('files',{}).values():
        if f.get('content'):
            print('YES'); sys.exit(0)
        elif f.get('raw_url'):
            print('RAW_URL_ONLY'); sys.exit(0)
print('NO')
" 2>/dev/null || echo "ERROR")
        
        if [ "$HAS_CONTENT" = "YES" ]; then
            pass "Gist files have inline content  -  scraper will work directly"
        elif [ "$HAS_CONTENT" = "RAW_URL_ONLY" ]; then
            warn "Gist files need raw_url fetch (code handles this, but slower)"
        else
            warn "Could not determine content format  -  needs runtime test"
        fi
    else
        fail "GitHub Gist API returned 0 gists or bad format"
    fi
fi

# Check rate limit
RATE_REMAINING=$(curl -sf "https://api.github.com/rate_limit" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['rate']['remaining'])" 2>/dev/null || echo "?")
info "GitHub API rate limit remaining: $RATE_REMAINING (60/hr without token, 5000/hr with)"
echo ""

# ─── TEST 2: Sourcegraph API ───
echo -e "${BOLD}TEST 2: Sourcegraph API (feeds ~35 IOC types)${NC}"
echo "────────────────────────────────────────"

# Try GraphQL first (more reliable to test)
SG_RESP=$(curl -sf -X POST "https://sourcegraph.com/.api/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"query{search(query:\"AKIA type:file count:3\",version:V3){results{matchCount results{...on FileMatch{repository{name}file{path}lineMatches{preview}}}}}}"}' 2>/dev/null || echo "CURL_FAILED")

if [ "$SG_RESP" = "CURL_FAILED" ]; then
    fail "Cannot reach sourcegraph.com  -  check internet"
else
    SG_COUNT=$(echo "$SG_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
results=d.get('data',{}).get('search',{}).get('results',{}).get('results',[])
print(len(results))
" 2>/dev/null || echo "0")
    
    SG_MATCH=$(echo "$SG_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
mc=d.get('data',{}).get('search',{}).get('results',{}).get('matchCount',0)
print(mc)
" 2>/dev/null || echo "0")
    
    if [ "$SG_COUNT" -gt "0" ]; then
        pass "Sourcegraph GraphQL API works  -  $SG_COUNT results, $SG_MATCH total matches for AKIA"
        
        # Show first result
        echo "$SG_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
results=d.get('data',{}).get('search',{}).get('results',{}).get('results',[])
if results:
    r=results[0]
    repo=r.get('repository',{}).get('name','?')
    path=r.get('file',{}).get('path','?')
    preview=r.get('lineMatches',[{}])[0].get('preview','')[:80] if r.get('lineMatches') else ''
    print(f'    First result: {repo}/{path}')
    print(f'    Preview: {preview}')
" 2>/dev/null
    else
        # Check for errors
        SG_ERROR=$(echo "$SG_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
errs=d.get('errors',[])
if errs: print(errs[0].get('message','unknown'))
else: print('no results')
" 2>/dev/null || echo "parse error")
        fail "Sourcegraph returned 0 results  -  $SG_ERROR"
    fi
    
    # Try stream API too
    STREAM_RESP=$(curl -sf "https://sourcegraph.com/.api/search/stream?q=AKIA+type:file+count:3&v=V3&display=3" 2>/dev/null | head -c 500 || echo "")
    if echo "$STREAM_RESP" | grep -q "matches\|repository"; then
        pass "Sourcegraph Stream API also works (primary mode)"
    else
        warn "Sourcegraph Stream API unclear  -  GraphQL fallback will be used"
    fi
fi
echo ""

# ─── TEST 3: Alt Paste Sites ───
echo -e "${BOLD}TEST 3: Alternative Paste Sites (feeds ~25 IOC types)${NC}"
echo "────────────────────────────────────────"

# dpaste.org
DPASTE_HTML=$(curl -sf "https://dpaste.org/" 2>/dev/null || echo "CURL_FAILED")
if [ "$DPASTE_HTML" = "CURL_FAILED" ]; then
    fail "Cannot reach dpaste.org"
else
    DPASTE_IDS=$(echo "$DPASTE_HTML" | grep -oP '(?<=href="/)[A-Za-z0-9]{4,12}' | sort -u | head -5)
    DPASTE_COUNT=$(echo "$DPASTE_IDS" | grep -c . 2>/dev/null || echo "0")
    if [ "$DPASTE_COUNT" -gt "0" ]; then
        FIRST_ID=$(echo "$DPASTE_IDS" | head -1)
        RAW=$(curl -sf "https://dpaste.org/$FIRST_ID/raw" 2>/dev/null | head -c 200 || echo "FAILED")
        if [ "$RAW" != "FAILED" ] && [ ${#RAW} -gt 10 ]; then
            pass "dpaste.org works  -  found $DPASTE_COUNT paste links, raw content fetches OK"
        else
            warn "dpaste.org lists pastes but raw fetch failed for $FIRST_ID"
        fi
    else
        warn "dpaste.org homepage has no visible paste links  -  parser may need update"
    fi
fi

# paste.centos.org
CENTOS_HTML=$(curl -sf "https://paste.centos.org/" 2>/dev/null || echo "CURL_FAILED")
if [ "$CENTOS_HTML" = "CURL_FAILED" ]; then
    warn "paste.centos.org unreachable (may be deprecated)"
else
    CENTOS_IDS=$(echo "$CENTOS_HTML" | grep -oP '(?<=href="/view/)[a-z0-9]+' | head -5)
    CENTOS_COUNT=$(echo "$CENTOS_IDS" | grep -c . 2>/dev/null || echo "0")
    if [ "$CENTOS_COUNT" -gt "0" ]; then
        pass "paste.centos.org works  -  found $CENTOS_COUNT paste links"
    else
        warn "paste.centos.org has no visible paste links"
    fi
fi

# paste.ubuntu.com
UBUNTU_HTML=$(curl -sf "https://paste.ubuntu.com/" 2>/dev/null || echo "CURL_FAILED")
if [ "$UBUNTU_HTML" = "CURL_FAILED" ]; then
    warn "paste.ubuntu.com unreachable"
else
    UBUNTU_IDS=$(echo "$UBUNTU_HTML" | grep -oP '(?<=href="/p/)[A-Za-z0-9]+' | head -5)
    UBUNTU_COUNT=$(echo "$UBUNTU_IDS" | grep -c . 2>/dev/null || echo "0")
    if [ "$UBUNTU_COUNT" -gt "0" ]; then
        pass "paste.ubuntu.com works  -  found $UBUNTU_COUNT paste links"
    else
        warn "paste.ubuntu.com has no visible paste links"
    fi
fi
echo ""

# ─── TEST 4: Pattern Matcher ───
echo -e "${BOLD}TEST 4: Pattern Matcher (100 IOC types)${NC}"
echo "────────────────────────────────────────"

PM_RESULT=$(docker exec arguswatch-backend python3 -c "
from arguswatch.engine.pattern_matcher import scan_text

test = '''
AWS key found: AKIA3EXAMPLEKEY12345 in production config
Stripe live: sk_live_EXAMPLE_REPLACE_ME
GitHub PAT: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
Database: DATABASE_URL=postgresql://admin:s3cret@db.company.com/prod
Private key found:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
Slack bot: xoxb-EXAMPLE-REPLACE-ME-TOKEN
Email combo: admin@company.com:P@ssw0rd2024!
OpenAI key: sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmn
CVE reference: CVE-2024-3400 critical vulnerability
IP seen: 185.215.113.97 scanning our network
Bitcoin ransom: send 5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Session: JSESSIONID=ABC123DEF456GHI789JKL012MNO345PQR
Config leak: .env file exposed with password=SuperSecret123!
S3 bucket: https://mybucket.s3.amazonaws.com/data/export.csv
'''
matches = scan_text(test)
print(f'TOTAL:{len(matches)}')
for m in matches:
    print(f'  {m.ioc_type}|{m.value[:50]}|{m.confidence}')
" 2>/dev/null || echo "DOCKER_FAILED")

if echo "$PM_RESULT" | grep -q "DOCKER_FAILED"; then
    fail "Cannot exec into backend container  -  is it running?"
elif echo "$PM_RESULT" | grep -q "TOTAL:"; then
    PM_COUNT=$(echo "$PM_RESULT" | grep "TOTAL:" | cut -d: -f2)
    if [ "$PM_COUNT" -gt "8" ]; then
        pass "Pattern matcher found $PM_COUNT IOCs in test text"
        echo "$PM_RESULT" | grep -v "TOTAL:" | head -15
    elif [ "$PM_COUNT" -gt "0" ]; then
        warn "Pattern matcher found only $PM_COUNT IOCs (expected 10+)"
        echo "$PM_RESULT" | grep -v "TOTAL:"
    else
        fail "Pattern matcher found 0 IOCs in test text with known patterns"
    fi
else
    fail "Pattern matcher import error: $(echo "$PM_RESULT" | tail -3)"
fi
echo ""

# ─── TEST 5: Compromise Search Endpoint ───
echo -e "${BOLD}TEST 5: Compromise Search API${NC}"
echo "────────────────────────────────────────"

CS_RESP=$(curl -sf "http://localhost:9010/search/compromise/admin@github.com" 2>/dev/null || echo "CURL_FAILED")
if [ "$CS_RESP" = "CURL_FAILED" ]; then
    fail "Compromise search endpoint not reachable at localhost:9010"
else
    CS_SOURCES=$(echo "$CS_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
sources=d.get('sources_checked',[])
print(f'SOURCES:{len(sources)}')
for s in sources:
    status='✅' if s['status']=='ok' else '⚠️'
    print(f'  {status} {s[\"name\"]}: {s[\"status\"]} ({s.get(\"hits\",0)} hits)')
qtype=d.get('query_type','?')
total=d.get('total_hits',0)
print(f'TYPE:{qtype}')
print(f'TOTAL_HITS:{total}')
" 2>/dev/null || echo "PARSE_ERROR")
    
    SOURCE_COUNT=$(echo "$CS_SOURCES" | grep "SOURCES:" | cut -d: -f2)
    if [ "$SOURCE_COUNT" -gt "2" ]; then
        pass "Compromise search checked $SOURCE_COUNT sources"
        echo "$CS_SOURCES" | grep -v "SOURCES:\|TYPE:\|TOTAL_HITS:"
    else
        warn "Compromise search returned few sources  -  check intel-proxy logs"
    fi
fi
echo ""

# ─── TEST 6: Trigger New Collectors ───
echo -e "${BOLD}TEST 6: Trigger New Collectors (THE REAL TEST)${NC}"
echo "────────────────────────────────────────"
info "This triggers real API calls and scans real data."
info "Takes 30-120 seconds depending on rate limits."
echo ""

for collector in github_gist sourcegraph alt_paste; do
    echo -e "  ${CYAN}Running $collector...${NC}"
    COLL_RESP=$(curl -sf -X POST "http://localhost:9010/collect/$collector" --max-time 120 2>/dev/null || echo "CURL_FAILED")
    
    if [ "$COLL_RESP" = "CURL_FAILED" ]; then
        fail "$collector  -  request failed or timed out"
    else
        NEW=$(echo "$COLL_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('new',0))" 2>/dev/null || echo "?")
        ERROR=$(echo "$COLL_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('error','none'))" 2>/dev/null || echo "?")
        
        if [ "$ERROR" != "none" ] && [ "$ERROR" != "?" ]; then
            fail "$collector  -  error: $ERROR"
        elif [ "$NEW" -gt "0" ] 2>/dev/null; then
            pass "$collector found $NEW new IOCs"
        else
            warn "$collector returned 0 IOCs (may be normal  -  depends on what's public right now)"
        fi
        
        # Show details
        echo "$COLL_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k,v in d.items():
    if k not in ('error',) and v:
        print(f'    {k}: {v}')
" 2>/dev/null | head -10
    fi
    echo ""
done

# ─── TEST 7: Check Database for Actual IOC Types Found ───
echo -e "${BOLD}TEST 7: IOC Types Actually Found in Database${NC}"
echo "────────────────────────────────────────"

DB_RESULT=$(docker exec arguswatch-backend python3 -c "
import asyncio
from arguswatch.database import async_session
from sqlalchemy import text
async def check():
    async with async_session() as db:
        r = await db.execute(text(
            \"SELECT source, ioc_type, COUNT(*) as ct FROM detections \"
            \"WHERE source IN ('github_gist','sourcegraph','dpaste','centos_paste','ubuntu_paste','paste_ee') \"
            \"GROUP BY source, ioc_type ORDER BY ct DESC\"
        ))
        rows = r.all()
        if not rows:
            print('NO_RESULTS')
        else:
            print(f'FOUND:{len(rows)} ioc_type combos')
            for row in rows:
                print(f'  {row[0]:20} {row[1]:30} {row[2]} detections')
asyncio.run(check())
" 2>/dev/null || echo "DOCKER_FAILED")

if echo "$DB_RESULT" | grep -q "DOCKER_FAILED"; then
    fail "Cannot query database  -  backend container issue"
elif echo "$DB_RESULT" | grep -q "NO_RESULTS"; then
    warn "No detections from new collectors yet  -  run TEST 6 first"
elif echo "$DB_RESULT" | grep -q "FOUND:"; then
    COMBO_COUNT=$(echo "$DB_RESULT" | grep "FOUND:" | cut -d: -f2 | cut -d' ' -f1)
    pass "Database has $COMBO_COUNT different IOC type combinations from new collectors"
    echo "$DB_RESULT" | grep -v "FOUND:"
fi
echo ""

# ─── TEST 8: AI Bar / Ollama ───
echo -e "${BOLD}TEST 8: AI Provider (Ollama + Qwen)${NC}"
echo "────────────────────────────────────────"

if docker ps --format '{{.Names}}' | grep -q "arguswatch-ollama"; then
    MODEL_READY=$(docker exec arguswatch-ollama test -f /tmp/.model_ready && echo "YES" || echo "NO")
    if [ "$MODEL_READY" = "YES" ]; then
        pass "Ollama running and Qwen model ready"
        # Quick test
        AI_RESP=$(curl -sf -X POST "http://localhost:8000/api/ai/query" \
            -H "Content-Type: application/json" \
            -d '{"query":"What is 2+2? Answer in one word.","provider":"ollama"}' --max-time 30 2>/dev/null || echo "FAILED")
        if echo "$AI_RESP" | grep -qi "four\|4"; then
            pass "Qwen responds correctly"
        elif [ "$AI_RESP" = "FAILED" ]; then
            warn "Qwen did not respond in 30 seconds  -  may still be loading"
        else
            info "Qwen response: $(echo "$AI_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('answer','?')[:80])" 2>/dev/null)"
        fi
    else
        warn "Ollama running but model still downloading  -  check: docker logs arguswatch-ollama"
    fi
else
    warn "Ollama container not running  -  AI bar will use keyword fallback"
fi
echo ""

# ─── SUMMARY ───
echo "══════════════════════════════════════════════════════════════"
echo -e "  ${BOLD}RESULTS${NC}"
echo "══════════════════════════════════════════════════════════════"
echo -e "  ${GREEN}PASS: $PASS${NC}"
echo -e "  ${RED}FAIL: $FAIL${NC}"
echo -e "  ${YELLOW}WARN: $WARN${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All critical tests passed.${NC}"
    echo "  Check TEST 7 output to see which of the 56 IOC types"
    echo "  were actually found in real data."
else
    echo -e "  ${RED}${BOLD}$FAIL test(s) failed.${NC}"
    echo "  Fix the failures above, then re-run this script."
fi
echo ""
echo "  Logs: docker logs arguswatch-intel-proxy 2>&1 | tail -50"
echo "  Dashboard: http://localhost:8000"
echo ""
