"""
ArgusWatch AI Agent Core V13 - AI is genuinely in the center.

WHAT CHANGED FROM V12:
  - Native tool/function calling for Anthropic + OpenAI (no more prompt-hacked JSON)
  - Ollama tool calling via API (supported in Ollama >=0.2 with llama3.1/qwen2.5)
  - Provider auto-detection: tries Anthropic → OpenAI → Ollama in order
  - Up to 10 iterations (was 5)
  - Pipeline AI hooks use this same LLM layer (severity, attribution, narrative, correlation)
  - Structured tool results - LLM can never hallucinate tool output
  - Provider health check endpoint support

PROVIDERS:
  - ollama      → local, private, free, needs `ollama pull qwen2.5:14b` or llama3.1:8b
  - anthropic   → claude-sonnet-4-5-20250929 (default)
  - openai      → gpt-4o (default)
  - auto        → try anthropic → openai → ollama, use first available
"""
import json
import logging
import httpx
from arguswatch.config import settings
from arguswatch.agent.tools import TOOL_REGISTRY, TOOL_SCHEMAS

logger = logging.getLogger("arguswatch.agent")

SYSTEM_PROMPT = """You are ArgusWatch AI - an expert cybersecurity threat intelligence analyst embedded inside a live threat detection platform.

You have access to tools that query REAL databases, call REAL threat intel APIs, and take REAL actions.
When you use a tool, you get back actual data from the system - not hypothetical data.

Your job:
1. Use tools to gather evidence before making any assessment
2. Cite specific IOC values, CVEs, actor names, severity levels from tool results
3. Give concrete, actionable recommendations with specific timeframes
4. Never guess when you can query

You are NOT a chatbot. You are an analyst with direct system access."""


# ══════════════════════════════════════════════════════════════════════
# NATIVE TOOL CALLING - Anthropic
# ══════════════════════════════════════════════════════════════════════

async def _call_anthropic(messages: list[dict], tools: list[dict]) -> dict:
    """Call Anthropic with native tool_use blocks. Returns structured response."""
    system_msgs = [m for m in messages if m["role"] == "system"]
    user_msgs = [m for m in messages if m["role"] != "system"]
    system_text = "\n\n".join(m["content"] for m in system_msgs) or SYSTEM_PROMPT

    # Convert OpenAI-style tool schemas to Anthropic format
    ant_tools = []
    for t in tools:
        ant_tools.append({
            "name": t["function"]["name"],
            "description": t["function"]["description"],
            "input_schema": t["function"]["parameters"],
        })

    payload = {
        "model": getattr(settings, "ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        "max_tokens": 2048,
        "system": system_text,
        "tools": ant_tools,
        "messages": user_msgs,
    }

    async with httpx.AsyncClient(timeout=45.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    # Parse Anthropic response into unified format
    stop_reason = data.get("stop_reason", "")
    content = data.get("content", [])

    tool_calls = []
    text_parts = []
    for block in content:
        if block.get("type") == "tool_use":
            tool_calls.append({
                "id": block["id"],
                "name": block["name"],
                "args": block.get("input", {}),
            })
        elif block.get("type") == "text":
            text_parts.append(block["text"])

    return {
        "provider": "anthropic",
        "stop_reason": stop_reason,  # "tool_use" or "end_turn"
        "tool_calls": tool_calls,
        "text": "\n".join(text_parts),
        "raw_content": content,  # needed to build next message
    }


# ══════════════════════════════════════════════════════════════════════
# NATIVE TOOL CALLING - OpenAI
# ══════════════════════════════════════════════════════════════════════

async def _call_openai(messages: list[dict], tools: list[dict]) -> dict:
    """Call OpenAI with native function calling. Returns structured response."""
    payload = {
        "model": getattr(settings, "OPENAI_MODEL", "gpt-4o"),
        "max_tokens": 2048,
        "tools": tools,
        "tool_choice": "auto",
        "messages": messages,
    }

    async with httpx.AsyncClient(timeout=45.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    msg = data["choices"][0]["message"]
    finish_reason = data["choices"][0]["finish_reason"]

    tool_calls = []
    if msg.get("tool_calls"):
        for tc in msg["tool_calls"]:
            try:
                args = json.loads(tc["function"]["arguments"])
            except Exception:
                args = {}
            tool_calls.append({
                "id": tc["id"],
                "name": tc["function"]["name"],
                "args": args,
            })

    return {
        "provider": "openai",
        "stop_reason": "tool_use" if finish_reason == "tool_calls" else "end_turn",
        "tool_calls": tool_calls,
        "text": msg.get("content") or "",
        "raw_message": msg,
    }


# ══════════════════════════════════════════════════════════════════════
# NATIVE TOOL CALLING - Ollama (tool_use API, qwen2.5/llama3.1+)
# ══════════════════════════════════════════════════════════════════════

async def _call_ollama(messages: list[dict], tools: list[dict]) -> dict:
    """Call Ollama with native tool calling (requires Ollama >=0.2 + compatible model)."""
    payload = {
        "model": settings.OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }
    # Only include tools if non-empty (empty tools array causes issues in some Ollama versions)
    if tools:
        payload["tools"] = tools

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{settings.OLLAMA_URL}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    msg = data.get("message", {})
    tool_calls_raw = msg.get("tool_calls", [])

    tool_calls = []
    for tc in tool_calls_raw:
        fn = tc.get("function", {})
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        tool_calls.append({
            "id": f"ollama_{fn.get('name', 'tool')}",
            "name": fn.get("name", ""),
            "args": args,
        })

    return {
        "provider": "ollama",
        "stop_reason": "tool_use" if tool_calls else "end_turn",
        "tool_calls": tool_calls,
        "text": msg.get("content") or "",
    }


async def _call_google(messages: list[dict], tools: list[dict]) -> dict:
    """Call Google Gemini API (gemini-2.5-pro default)."""
    # Convert messages to Gemini format
    gemini_contents = []
    system_text = ""
    for m in messages:
        if m["role"] == "system":
            system_text = m["content"]
        elif m["role"] == "model":
            # Already in Gemini format (from tool loop)
            gemini_contents.append(m)
        elif m["role"] == "user":
            # Could be text or functionResponse parts (from tool loop)
            if "parts" in m:
                gemini_contents.append(m)
            elif isinstance(m.get("content"), str):
                gemini_contents.append({"role": "user", "parts": [{"text": m["content"]}]})
        elif m["role"] == "assistant":
            # Plain text from initial messages
            content = m.get("content", "")
            if isinstance(content, str) and content:
                gemini_contents.append({"role": "model", "parts": [{"text": content}]})

    model = getattr(settings, "GOOGLE_AI_MODEL", "gemini-2.5-pro")
    payload = {
        "contents": gemini_contents,
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096},
    }
    if system_text:
        payload["systemInstruction"] = {"parts": [{"text": system_text}]}

    # Convert tools to Gemini function declarations
    if tools:
        fn_decls = []
        for t in tools:
            fn = t.get("function", t)
            fn_decls.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "parameters": fn.get("parameters", fn.get("input_schema", {})),
            })
        payload["tools"] = [{"functionDeclarations": fn_decls}]

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            f"?key={settings.GOOGLE_AI_API_KEY}",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    # Parse response
    candidates = data.get("candidates", [{}])
    parts = candidates[0].get("content", {}).get("parts", []) if candidates else []

    text = ""
    tool_calls = []
    for part in parts:
        if "text" in part:
            text += part["text"]
        if "functionCall" in part:
            fc = part["functionCall"]
            tool_calls.append({
                "id": f"google_{fc.get('name', 'tool')}",
                "name": fc.get("name", ""),
                "args": fc.get("args", {}),
            })

    return {
        "provider": "google",
        "stop_reason": "tool_use" if tool_calls else "end_turn",
        "tool_calls": tool_calls,
        "text": text,
    }


# ══════════════════════════════════════════════════════════════════════
# PROVIDER HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════

async def check_provider_health() -> dict:
    """Check which providers are available right now."""
    status = {}

    # Anthropic
    if settings.ANTHROPIC_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
                    json={"model": settings.ANTHROPIC_MODEL, "max_tokens": 10, "messages": [{"role": "user", "content": "ping"}]},
                )
            status["anthropic"] = "ok" if r.status_code == 200 else f"error:{r.status_code}"
        except Exception as e:
            status["anthropic"] = f"unreachable:{e}"
    else:
        status["anthropic"] = "no_key"

    # OpenAI
    if settings.OPENAI_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                )
            status["openai"] = "ok" if r.status_code == 200 else f"error:{r.status_code}"
        except Exception as e:
            status["openai"] = f"unreachable:{e}"
    else:
        status["openai"] = "no_key"

    # Ollama
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.OLLAMA_URL}/api/tags")
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            has_model = any(settings.OLLAMA_MODEL.split(":")[0] in m for m in models)
            status["ollama"] = "ok" if has_model else f"running_but_no_{settings.OLLAMA_MODEL}"
        else:
            status["ollama"] = f"error:{r.status_code}"
    except Exception as e:
        status["ollama"] = f"unreachable:{e}"

    # Google Gemini
    if getattr(settings, "GOOGLE_AI_API_KEY", ""):
        try:
            model = getattr(settings, "GOOGLE_AI_MODEL", "gemini-2.5-pro")
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}"
                    f"?key={settings.GOOGLE_AI_API_KEY}",
                )
            status["google"] = "ok" if r.status_code == 200 else f"error:{r.status_code}"
        except Exception as e:
            status["google"] = f"unreachable:{e}"
    else:
        status["google"] = "no_key"

    return status


def _resolve_provider(requested: str) -> str:
    """Resolve 'auto' to user-selected provider (AI_ACTIVE_PROVIDER).
    Falls back through: selected → ollama → any available."""
    if requested != "auto":
        return requested
    # Use user's active provider selection from dashboard
    selected = getattr(settings, "AI_ACTIVE_PROVIDER", "ollama")
    if selected != "auto":
        return selected
    # True auto: fallback chain
    if settings.ANTHROPIC_API_KEY:
        return "anthropic"
    if settings.OPENAI_API_KEY:
        return "openai"
    if getattr(settings, "GOOGLE_AI_API_KEY", ""):
        return "google"
    return "ollama"


# ══════════════════════════════════════════════════════════════════════
# MAIN AGENT LOOP - native tool calling, all providers
# ══════════════════════════════════════════════════════════════════════

async def run_agent(
    question: str,
    provider: str = "auto",
    conversation_history: list[dict] | None = None,
    max_iterations: int = 10,
) -> dict:
    """
    Run the ArgusWatch AI agent loop with NATIVE tool calling.

    The LLM genuinely decides which tools to call based on the question.
    Tool results are fed back as structured data - LLM cannot hallucinate them.
    """
    provider = _resolve_provider(provider)

    # Build message history
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if conversation_history:
        messages.extend(conversation_history)
    messages.append({"role": "user", "content": question})

    tools_used = []
    tool_results = []

    for iteration in range(max_iterations):
        # ── Call LLM with native tool definitions ────────────────────────
        try:
            if provider == "anthropic":
                response = await _call_anthropic(messages, TOOL_SCHEMAS)
            elif provider == "openai":
                response = await _call_openai(messages, TOOL_SCHEMAS)
            elif provider == "ollama":
                response = await _call_ollama(messages, TOOL_SCHEMAS)
            elif provider == "google":
                response = await _call_google(messages, TOOL_SCHEMAS)
            else:
                return {"answer": f"Unknown provider: {provider}", "tools_used": [], "iterations": 0}
        except httpx.HTTPStatusError as e:
            return {
                "answer": f"{provider} API error {e.response.status_code}: {e.response.text[:300]}",
                "tools_used": tools_used,
                "iterations": iteration + 1,
                "provider": provider,
            }
        except Exception as e:
            return {
                "answer": f"{provider} unavailable: {e}",
                "tools_used": tools_used,
                "iterations": iteration + 1,
                "provider": provider,
            }

        # ── No tool calls → LLM is done ──────────────────────────────────
        if response["stop_reason"] == "end_turn" or not response["tool_calls"]:
            return {
                "answer": response["text"] or "Analysis complete.",
                "tools_used": tools_used,
                "tool_results": tool_results,
                "iterations": iteration + 1,
                "provider": provider,
                "model": (
                    settings.OLLAMA_MODEL if provider == "ollama"
                    else getattr(settings, f"{provider.upper()}_MODEL", provider)
                ),
            }

        # ── Execute tool calls (LLM chose these - not us) ────────────────
        if provider == "anthropic":
            # Add assistant message with tool_use blocks
            messages.append({"role": "assistant", "content": response["raw_content"]})
            tool_result_blocks = []
        elif provider == "openai":
            messages.append({"role": "assistant", **response["raw_message"]})
        elif provider == "google":
            # Gemini: model turn with functionCall parts
            fc_parts = []
            if response.get("text"):
                fc_parts.append({"text": response["text"]})
            for tc in response["tool_calls"]:
                fc_parts.append({"functionCall": {"name": tc["name"], "args": tc["args"]}})
            messages.append({"role": "model", "parts": fc_parts})
            _google_tool_responses = []  # collect for batch append
        else:  # ollama
            messages.append({"role": "assistant", "content": response["text"] or "", "tool_calls": [
                {"function": {"name": tc["name"], "arguments": tc["args"]}} for tc in response["tool_calls"]
            ]})

        for tc in response["tool_calls"]:
            tool_name = tc["name"]
            tool_args = tc["args"]

            if tool_name not in TOOL_REGISTRY:
                result = {"error": f"Tool '{tool_name}' not found in registry"}
            else:
                try:
                    result = await TOOL_REGISTRY[tool_name](**tool_args)
                    tools_used.append(tool_name)
                    tool_results.append({"tool": tool_name, "args": tool_args, "result": result})
                    logger.info(f"[agent] tool={tool_name} args={tool_args} result_keys={list(result.keys()) if isinstance(result, dict) else type(result).__name__}")
                except Exception as e:
                    logger.error(f"[agent] Tool {tool_name} failed: {e}")
                    result = {"error": str(e), "tool": tool_name}

            result_str = json.dumps(result, default=str)[:3000]

            # Append tool result in provider-specific format
            if provider == "anthropic":
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": tc["id"],
                    "content": result_str,
                })
            elif provider == "openai":
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result_str,
                })
            elif provider == "google":
                _google_tool_responses.append({
                    "functionResponse": {
                        "name": tc["name"],
                        "response": {"content": result_str},
                    }
                })
            else:  # ollama
                messages.append({
                    "role": "tool",
                    "content": result_str,
                })

        # For Anthropic: add all tool results as one user message
        if provider == "anthropic" and tool_result_blocks:
            messages.append({"role": "user", "content": tool_result_blocks})

        # For Google: add all functionResponses as one user turn
        if provider == "google" and _google_tool_responses:
            messages.append({"role": "user", "parts": _google_tool_responses})

    # Hit max iterations
    return {
        "answer": (
            f"Reached {max_iterations} iterations. "
            f"Tools used: {', '.join(tools_used)}. "
            "Review tool_results for the data gathered."
        ),
        "tools_used": tools_used,
        "tool_results": tool_results,
        "iterations": max_iterations,
        "provider": provider,
    }


# ══════════════════════════════════════════════════════════════════════
# PIPELINE AI CALLS - same LLM, used directly by ingest_pipeline steps
# ══════════════════════════════════════════════════════════════════════

async def ai_assess_severity(
    ioc_type: str,
    ioc_value: str,
    enrichment_data: dict,
    context: dict,
    provider: str = "auto",
) -> dict:
    """
    Pipeline Step 5 AI hook: LLM decides severity from enrichment evidence.
    Returns: {severity, sla_hours, confidence, reasoning}
    Falls back to rule-based scorer if LLM unavailable.
    """
    provider = _resolve_provider(provider)
    prompt = f"""Given this enrichment data, assess the severity of this IOC:

IOC: {ioc_value} (type: {ioc_type})
VT malicious detections: {enrichment_data.get('vt_malicious', 'N/A')}
AbuseIPDB score: {enrichment_data.get('abuse_score', 'N/A')}
OTX pulse count: {enrichment_data.get('otx_pulses', 'N/A')}
Customer industry: {context.get('industry', 'unknown')}
Customer asset match: {context.get('asset_match', 'none')}
Source feed: {context.get('source', 'unknown')}

Respond ONLY as JSON: {{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "sla_hours": <int>, "confidence": <0.0-1.0>, "reasoning": "<one sentence>"}}"""

    try:
        if provider == "anthropic":
            response = await _call_anthropic(
                [{"role": "system", "content": "You are a cybersecurity severity classifier. Always respond with valid JSON only."},
                 {"role": "user", "content": prompt}],
                []  # no tools needed for this
            )
            text = response["text"]
        elif provider == "openai":
            response = await _call_openai(
                [{"role": "system", "content": "You are a cybersecurity severity classifier. Always respond with valid JSON only."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = response["text"]
        elif provider == "ollama":
            response = await _call_ollama(
                [{"role": "system", "content": "You are a cybersecurity severity classifier. Respond ONLY with JSON."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = response["text"]
        elif provider == "google":
            response = await _call_google(
                [{"role": "system", "content": "You are a cybersecurity severity classifier. Respond ONLY with JSON."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = response["text"]
        else:
            return {}

        # Parse JSON from response
        import re
        m = re.search(r'\{[^{}]+\}', text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception as e:
        logger.debug(f"[ai_severity] fallback to rules: {e}")
    return {}  # caller falls back to rule-based scorer


async def ai_attribution_narrative(
    ioc_value: str,
    ioc_type: str,
    candidate_actors: list[dict],
    finding_context: dict,
    provider: str = "auto",
) -> dict:
    """
    Pipeline Step 6 AI hook: LLM picks most likely actor from candidates + writes narrative.
    Returns: {actor_name, confidence, narrative}
    """
    if not candidate_actors:
        return {}

    provider = _resolve_provider(provider)
    actors_summary = "\n".join(
        f"- {a.get('name')}: targets {a.get('target_sectors','?')}, uses {a.get('techniques','?')}"
        for a in candidate_actors[:5]
    )
    prompt = f"""IOC: {ioc_value} ({ioc_type})
Customer industry: {finding_context.get('industry', 'unknown')}
Customer geography: {finding_context.get('country', 'unknown')}

Candidate threat actors from database:
{actors_summary}

Which actor is most likely responsible? Respond ONLY as JSON:
{{"actor_name": "<name or null>", "confidence": <0.0-1.0>, "narrative": "<2 sentence investigation narrative>"}}"""

    try:
        if provider == "anthropic":
            r = await _call_anthropic(
                [{"role": "system", "content": "You are a threat attribution analyst. JSON only."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = r["text"]
        elif provider == "openai":
            r = await _call_openai(
                [{"role": "system", "content": "You are a threat attribution analyst. JSON only."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = r["text"]
        elif provider == "ollama":
            r = await _call_ollama(
                [{"role": "system", "content": "You are a threat attribution analyst. Respond ONLY with JSON."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = r["text"]
        elif provider == "google":
            r = await _call_google(
                [{"role": "system", "content": "You are a threat attribution analyst. Respond ONLY with JSON."},
                 {"role": "user", "content": prompt}],
                []
            )
            text = r["text"]
        else:
            return {}

        import re
        m = re.search(r'\{[^{}]+\}', text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception as e:
        logger.debug(f"[ai_attribution] failed: {e}")
    return {}


async def ai_investigation_narrative(
    finding_id: int,
    ioc_value: str,
    ioc_type: str,
    enrichment_summary: dict,
    actor_name: str | None,
    customer_name: str | None,
    provider: str = "auto",
) -> str:
    """
    Pipeline Step 5 AI hook: generate investigation narrative stored on the finding.
    Returns a 2-3 sentence analyst narrative string.
    """
    provider = _resolve_provider(provider)
    prompt = f"""Write a concise 2-3 sentence investigation narrative for this finding:

IOC: {ioc_value} ({ioc_type})
Customer: {customer_name or 'unknown'}
Attributed actor: {actor_name or 'unknown'}
VT detections: {enrichment_summary.get('vt_malicious', 'N/A')}
AbuseIPDB score: {enrichment_summary.get('abuse_score', 'N/A')}

Write as a senior SOC analyst writing for an executive briefing. Be specific. Do not use placeholder text."""

    try:
        if provider == "anthropic":
            r = await _call_anthropic(
                [{"role": "system", "content": "You are a SOC analyst writing executive briefings. Be concise and specific."},
                 {"role": "user", "content": prompt}],
                []
            )
            return r["text"].strip()
        elif provider == "openai":
            r = await _call_openai(
                [{"role": "system", "content": "You are a SOC analyst writing executive briefings."},
                 {"role": "user", "content": prompt}],
                []
            )
            return r["text"].strip()
        elif provider == "ollama":
            r = await _call_ollama(
                [{"role": "system", "content": "You are a SOC analyst writing executive briefings. Be concise."},
                 {"role": "user", "content": prompt}],
                []
            )
            return r["text"].strip()
        elif provider == "google":
            r = await _call_google(
                [{"role": "system", "content": "You are a SOC analyst writing executive briefings. Be concise."},
                 {"role": "user", "content": prompt}],
                []
            )
            return r["text"].strip()
    except Exception as e:
        logger.debug(f"[ai_narrative] failed: {e}")
    return ""
