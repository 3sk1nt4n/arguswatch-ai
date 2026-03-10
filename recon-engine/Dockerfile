FROM golang:1.22-bookworm AS tools

# Install ProjectDiscovery tools via go install (most reliable method)
ENV GOBIN=/tools
RUN mkdir -p /tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# ── Final image ──
FROM python:3.11-slim

# System recon tools (always available)
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils whois nmap curl wget ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Copy Go-built tools (may be empty if build failed — recon_server handles gracefully)
COPY --from=tools /tools/ /usr/local/bin/

# Python deps
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn httpx sqlalchemy asyncpg aiofiles

COPY recon_server.py .
EXPOSE 9001
CMD ["uvicorn", "recon_server:app", "--host", "0.0.0.0", "--port", "9001", "--log-level", "info"]
