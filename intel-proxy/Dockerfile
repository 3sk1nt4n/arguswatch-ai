FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx sqlalchemy asyncpg

# Copy the proxy server
COPY intel-proxy/proxy_server.py .

# Copy pattern_matcher + severity_scorer from backend
# These are stdlib-only (re, dataclasses) — no extra deps needed.
# Without these, paste and grep_app collectors silently skip all IOC extraction.
# This unlocks Cat 1, 2, 7, 10, 11 in one fix.
RUN mkdir -p arguswatch/engine
RUN touch arguswatch/__init__.py arguswatch/engine/__init__.py
COPY backend/arguswatch/engine/pattern_matcher.py arguswatch/engine/
COPY backend/arguswatch/engine/severity_scorer.py arguswatch/engine/

CMD ["uvicorn", "proxy_server:app", "--host", "0.0.0.0", "--port", "9000", "--log-level", "info"]
