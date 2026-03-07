# ArgusWatch — Agentic AI: Honest Assessment

## The Agentic AI Spectrum

```
LEVEL 0: Static Rules          ← Most of ArgusWatch today
LEVEL 1: AI-Assisted           ← Chat bar, severity scoring
LEVEL 2: AI-Decided            ← Triage hooks (severity/FP/narrative)  
LEVEL 3: AI-Autonomous (Loop)  ← 9-tool Orchestrator ✅ EXISTS
LEVEL 4: AI-Initiated          ← NOT YET (AI decides WHEN to act)
LEVEL 5: Multi-Agent Swarm     ← NOT YET (agents coordinate)
```

## What IS Genuinely Agentic Today

### ✅ 9-Tool Orchestrator (Level 3)
The ONE truly agentic component. Given a detection, the AI:
1. Receives a goal: "Investigate and assess this IOC"
2. AUTONOMOUSLY picks which tool to call first
3. Executes the tool, observes the result
4. Decides what to do next based on what it learned
5. Iterates up to 4 times (Ollama) or 12 times (Claude/GPT)
6. Produces a final assessment with evidence

Example autonomous decision chain:
```
Detection: "CVE-2026-3404 found in Uber's tech stack"
  → AI calls query_customers(name="Uber") → sees industry=transportation
  → AI calls search_cve("CVE-2026-3404") → sees CVSS 8.1, affects Java
  → AI calls check_exposure(customer_id=4) → sees D1=45, high surface area  
  → AI calls query_actors(target_sector="transportation") → finds APT41
  → FINAL: "CRITICAL — CVE actively exploited, Uber runs Java, APT41 targets transport"
```

This is real agentic behavior: goal → autonomous tool selection → observation → reasoning → next action.

### ✅ AI Triage Hooks (Level 2)
AI makes autonomous DECISIONS without human approval:
- Severity: AI overrides rule-based scoring with evidence-based reasoning
- False Positive: AI flags likely FPs before analyst sees them
- Narrative: AI writes investigation context from raw data

### ✅ FP Memory (Level 2 — Learning)
System learns from analyst decisions:
- Analyst marks finding as FP → pattern recorded
- Next time similar IOC appears → auto-flagged
- This is genuine machine learning (pattern → decision), not just rules

## What is NOT Agentic (Honest Labels)

### ❌ 47 Collectors = AUTOMATION (Level 0)
Cron job fetches URL, parses JSON, stores in DB.
No intelligence. No decisions. Just scheduled HTTP.
**Honest label: "Automated Collection Pipeline"**

### ❌ 8 Matching Strategies = DETERMINISTIC RULES (Level 0)
`if domain in customer_domains → match`
`if edit_distance(brand, domain) <= 2 → typosquat`
Pure logic. No AI. No learning.
**Honest label: "Rule-Based Correlation Engine"**

### ❌ 86 IOC Patterns = STATIC REGEX (Level 0)
`r'AKIA[0-9A-Z]{16}'` matches AWS keys.
Written once, never adapts. Misses new formats until human updates regex.
**Honest label: "Pattern-Based IOC Scanner"**

### ❌ 12 Remediation Playbooks = TEMPLATES (Level 0)
`if ioc_type == "leaked_api_key" → generate 6 response steps`
Same steps every time. No customization based on context.
**Honest label: "Playbook-Based Remediation Generator"**

### ❌ Exposure Scoring = MATH (Level 0)
`score = D1*0.45 + D2*0.20 + D3*0.15 + D4*0.10 + D5*0.10`
Weighted formula. Not intelligence.
**Honest label: "Formula-Based Risk Scoring"**

### ❌ Chat Bar = Q&A (Level 1)
User asks → prompt built → LLM responds → displayed.
No tool calling. No iteration. No autonomous action.
**Honest label: "AI-Powered Q&A Interface"**

## What Would Make It FULLY Agentic (Level 4-5)

### Level 4: AI-Initiated Actions
Today: Human clicks "Collect" → collectors run → matching runs → AI triages
Agentic: AI DECIDES when to collect, what to prioritize, which customers need attention

Concrete features needed:
1. **Autonomous Alert Escalation** — AI sees CRITICAL finding → auto-notifies Slack/email → auto-creates Jira ticket → no human trigger needed
2. **Smart Collection** — AI notices customer has new subdomain → auto-runs crt.sh + Shodan for that domain → creates findings if exposed
3. **Proactive Hunt** — AI sees ransomware actor targeting retail → auto-checks all retail customers' exposure → generates pre-emptive report
4. **Self-Improving Patterns** — AI finds new credential format in paste site → auto-generates new regex → adds to pattern_matcher → starts detecting

### Level 5: Multi-Agent Coordination
Multiple AI agents working together:
1. **Collection Agent** — decides what to collect and when
2. **Triage Agent** — assesses every finding (EXISTS today)
3. **Hunt Agent** — proactively searches for threats
4. **Remediation Agent** — customizes response steps per customer context
5. **Report Agent** — generates customer-specific briefings
6. **Coordinator Agent** — assigns work to other agents based on priority

## Honest Marketing vs Reality

### Current README says:
"7 autonomous AI agents"

### Reality:
- 1 truly autonomous agent (9-tool orchestrator)
- 3 AI decision hooks (triage, FP, narrative)  
- 1 learning system (FP memory)
- Everything else is rule-based automation

### Honest version:
"1 autonomous AI agent with 9 tools, 3 AI decision hooks, and 
rule-based automation across 47 collectors and 8 matching strategies"

## Summary: The Honest Agentic Score

| Component | Level | Label |
|-----------|-------|-------|
| 9-Tool Orchestrator | 3 - Autonomous Loop | ✅ AGENTIC |
| AI Triage (severity) | 2 - AI-Decided | ✅ Semi-Agentic |
| AI FP Check | 2 - AI-Decided | ✅ Semi-Agentic |
| AI Narrative | 2 - AI-Decided | ✅ Semi-Agentic |
| FP Memory | 2 - Learning | ✅ Semi-Agentic |
| Chat Bar | 1 - AI-Assisted | ❌ Not Agentic |
| Collectors | 0 - Automation | ❌ Not Agentic |
| Matching Engine | 0 - Rules | ❌ Not Agentic |
| IOC Patterns | 0 - Static | ❌ Not Agentic |
| Playbooks | 0 - Templates | ❌ Not Agentic |
| Exposure Score | 0 - Formula | ❌ Not Agentic |

**Overall: ~25% genuinely agentic, ~75% well-engineered automation.**

This is HONEST. And honestly? That 25% (the orchestrator + triage hooks) 
is more agentic than most "AI-powered" security tools on the market, which 
are typically 0% agentic (just dashboards with an LLM chatbot bolted on).

The path from 25% → 75% agentic is the Level 4-5 features above.
