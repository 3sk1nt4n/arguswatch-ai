from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Database
    POSTGRES_USER: str = "arguswatch"
    POSTGRES_PASSWORD: str = "arguswatch_dev_2026"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "arguswatch"
    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/1"
    # Intel Proxy Gateway (enterprise architecture - separate service with internet access)
    INTEL_PROXY_URL: str = "http://intel-proxy:9000"
    # AI
    OLLAMA_URL: str = "http://ollama:11434"
    AI_AUTONOMOUS: bool = False  # Default safe. docker-compose sets True (Ollama guaranteed). Without docker: rules-only until AI verified
    OLLAMA_MODEL: str = "qwen2.5:14b"
    # Active provider: "ollama" (default local), "anthropic", "openai", "google", or "auto" (best available)
    AI_ACTIVE_PROVIDER: str = "ollama"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"    # Best balance of intelligence + speed
    OPENAI_MODEL: str = "gpt-4o"                            # Most capable GPT model
    GOOGLE_AI_API_KEY: str = ""
    GOOGLE_AI_MODEL: str = "gemini-2.5-pro"                  # Most capable Gemini model
    # SIEM output
    SYSLOG_HOST: str = ""
    SYSLOG_PORT: int = 514
    STIX_OUTPUT_DIR: str = "/tmp/stix_out"
    # Alerts
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    ALERT_EMAIL: str = ""
    CISO_EMAIL: str = ""
    # Free APIs (no cost)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    # Collector source URLs (free public feeds)
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    MITRE_ATTACK_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    THREATFOX_URL: str = "https://threatfox-api.abuse.ch/api/v1/"
    FEODO_URL: str = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    MALWAREBAZAAR_URL: str = "https://mb-api.abuse.ch/api/v1/"
    OPENPHISH_URL: str = "https://openphish.com/feed.txt"
    RANSOMFEED_URL: str = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
    ABUSEIPDB_URL: str = "https://api.abuseipdb.com/api/v2/blacklist"
    HUDSONROCK_URL: str = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
    # Discovery providers (GAP 1/7 fix)
    SECURITYTRAILS_API_KEY: str = ""  # Enables subdomain enumeration + DNS history + WHOIS
    AGENT_SIGNING_KEY: str = ""       # HMAC-SHA256 key for validating agent bundles
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    GITHUB_TOKEN: str = ""
    INTELX_API_KEY: str = ""
    DARKSEARCH_API_KEY: str = ""
    PULSEDIVE_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""   # Optional - improves rate limits
    GREYNOISE_API_KEY: str = ""
    # Telegram (free - your account)
    TELEGRAM_API_ID: str = ""
    TELEGRAM_API_HASH: str = ""
    TELEGRAM_CHANNELS: str = ""
    # HIBP ($3.50/mo - all 3 endpoints)
    HIBP_API_KEY: str = ""
    BREACHDIRECTORY_API_KEY: str = ""
    # SocRadar + Hudson Rock (free tiers)
    SOCRADAR_API_KEY: str = ""
    HUDSON_ROCK_API_KEY: str = ""
    # ServiceNow (optional - free with your instance)
    SERVICENOW_INSTANCE: str = ""
    SERVICENOW_USER: str = ""
    SERVICENOW_PASS: str = ""
    # ── ENTERPRISE - architecture wired, key-activated ──
    SPYCLOUD_API_KEY: str = ""
    CYBERSIXGILL_CLIENT_ID: str = ""
    CYBERSIXGILL_SECRET: str = ""
    RECORDED_FUTURE_KEY: str = ""
    CYBERINT_API_KEY: str = ""
    FLARE_API_KEY: str = ""
    CROWDSTRIKE_CLIENT_ID: str = ""
    CROWDSTRIKE_SECRET: str = ""
    CYWARE_TAXII_URL: str = ""

    @property
    def DATABASE_URL_ASYNC(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
    @property
    def DATABASE_URL_SYNC(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
    @property
    def SYNC_DATABASE_URL(self) -> str:
        return self.DATABASE_URL_SYNC

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
