# ArgusWatch AI -  Honest Assessment (v16.4.7 Session B)

**Date:** March 9, 2026  
**Author:** Honest code review, not marketing  

---

## What Actually Adds Value vs If-Else

| Component | Honest Label | Better Than Code? |
|-----------|-------------|------------------|
| **AI Bar** | ✅ **Genuinely Agentic** | **YES** -  regex classifies IOC (0ms, perfect), compromise API checks sources (2-10s), then LLM reasons about results, decides what to investigate next (check findings? exposure? actors? related emails?), runs follow-up queries, writes analyst brief. The LLM DECIDES the investigation path -  code doesn't predetermine it. |
| **Investigation Narrative** | AI-Generated | **YES** -  can't replicate analyst-quality writeups with templates |
| **Reliable Chat Agent** | Classify->Query->Summarize | **YES** -  NL queries against live DB with triple fallback |
| 9-Tool Orchestrator | Agentic but redundant | **No** -  linear pipeline does same thing in 50ms |
| Severity Triage | Single LLM lottery | **No** -  IOC v10 spreadsheet IS the lookup table |
| FP Check (AI hook) | Single LLM call | **No** -  12 HIGH-FP types already identified |
| AI Remediation | Template + LLM polish | **Marginal** -  template substitution gets 80% there |
| AI Match Confidence | Single LLM scorer | **No** -  heuristic is better |
| FP Memory | Hit counter + CIDR | **Not ML** but useful automation |
| RAG Context | SQL relevance queries | **Not RAG** but useful context enrichment |

---

## What's Genuinely Agentic (Updated)

**3 components are genuinely agentic** (LLM controls execution flow):

### 1. AI Bar Investigation Agent (NEW)
- Regex classifies IOC -> compromise check runs -> **LLM sees results and DECIDES** what to investigate
- The LLM picks from: check_customer_findings, check_exposure, check_related_emails, check_threat_actors, check_darkweb, check_remediations, or skip
- Python executes the chosen queries deterministically
- LLM synthesizes an analyst brief from all gathered data
- **Why it's real:** Remove the LLM and the investigation doesn't happen. The code doesn't predetermine which follow-ups to run.
- **What's NOT agentic:** IOC classification (regex, 100% accurate, 0ms) and compromise API calls (deterministic). Those stay as automation because they're better that way.

### 2. 9-Tool Orchestrator
- LLM gets 9 tool schemas + detection ID, decides the sequence
- **Real but redundant** -  the linear pipeline runs the same steps in 50ms

### 3. Chat Agent (tool-calling mode)
- LLM picks from 6 query tools, gets real DB results, decides next step
- **Real but fragile** -  the reliable two-phase `/api/ai/chat` is safer for local models

---

## AI Bar: Honest Timing Breakdown

Every AI Bar response includes timing for full transparency:

| Phase | What happens | Who does it | Time (local) | Time (cloud) |
|-------|-------------|------------|-------------|-------------|
| Classify | Regex detects IOC type | JavaScript | 0ms | 0ms |
| Compromise | Check HudsonRock, HIBP, VT, grep.app | Python API | 2-10s | 2-10s |
| Phase 1 | LLM decides what to investigate next | **LLM** | 15-30s | 2-5s |
| Phase 2 | Execute follow-up DB queries | Python SQL | <1s | <1s |
| Phase 3 | LLM writes analyst brief | **LLM** | 15-30s | 2-5s |
| **Total** | | | **35-70s** | **7-20s** |

The response card shows 🤖 for LLM steps and ⚡ for instant steps. No hiding what's slow.

---

## Top 10 AI Models -  Local + Cloud (March 2026)

*Hardware: AMD Ryzen 9 9950X3D · 64GB DDR5 · ~17GB VRAM*

| # | Model | Type | Size | Speed | GPQA | SWE-bench | Context | Tools | Cost (in/out) |
|---|-------|------|------|-------|------|-----------|---------|-------|---------------|
| 🥇 | **Qwen 3.5 9B** ← OUR DEFAULT | 🟢 LOCAL | 6.6 GB | 40-60 t/s | 81.7 | -  | 256K | ✅ RL-trained | **FREE** |
| 🥈 | **Gemini 3.1 Pro** ← BEST VALUE | 🟣 CLOUD | Proprietary | 50-70 t/s | **94.3** 🏆 | 80.6% | 1M | ✅ Native+MCP | $2 / $12 |
| 🥉 | **Claude Opus 4.6** ← DEEPEST | 🟣 CLOUD | Proprietary | 25-35 t/s | 91.3 | **80.8%** | 1M | ✅ Native | $5 / $25 |
| 4 | **GPT-5.3 Codex** ← BEST CODING | 🟣 CLOUD | Proprietary | 40-60 t/s | 81.0 | 56.8% Pro | 400K | ✅ Native | $1.75 / $14 |
| 5 | GPT-OSS 20B | 🟢 LOCAL | ~13 GB | 80-140 t/s | ~72 | -  | 128K | ✅ Native | **FREE** |
| 6 | GLM-4.6V Flash 9B | 🟢 LOCAL | ~6 GB | 45-65 t/s | ~65 | -  | 128K | ✅ 87.4% τ² | **FREE** |
| 7 | Qwen 3 14B | 🟢 LOCAL | ~8.5 GB | 35-50 t/s | ~68 | -  | 128K | ✅ Yes | **FREE** |
| 8 | Qwen 3.5 4B | 🟢 LOCAL | 2.7 GB | 80-120 t/s | ~70 | -  | 256K | ✅ RL-trained | **FREE** |
| 9 | Qwen3-Coder-Next 80B-A3B | 🟢 LOCAL | ~14 GB | 25-40 t/s | ~75 | 70.6% | 256K | ✅ Strong | **FREE** |
| 10 | Gemma 3 12B | 🟢 LOCAL | ~8 GB | 35-50 t/s | ~60 | -  | 128K | ⚠️ Limited | **FREE** |

**Strategy:** Default to Qwen 3.5 9B locally (free, private). One-click to Gemini 3.1 Pro for best-value cloud. One-click to Claude Opus 4.6 for deepest reasoning. One-click to GPT-5.3 Codex for coding/terminal. All four already wired in ArgusWatch.

> **⚠️ Benchmark verification:** Scores sourced from Artificial Analysis, Google DeepMind model cards, Anthropic release posts, OpenAI announcements, and VentureBeat (Feb-Mar 2026). Verify current numbers at [artificialanalysis.ai](https://artificialanalysis.ai) before using in customer-facing materials. Model availability and pricing change frequently.

---

## Bottom Line

Three components where AI genuinely adds value code can't replicate: the AI Bar (agentic investigation after compromise check), investigation narratives, and the reliable chat agent. The AI Bar is the centerpiece -  it sits in the middle of everything, auto-classifies every IOC type, checks every source, and then the LLM investigates what the results mean. That's a real agent.
