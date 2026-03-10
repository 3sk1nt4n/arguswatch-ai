from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, field_validator

SEVERITY_VALUES = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUS_VALUES = Literal["NEW", "ENRICHED", "ALERTED", "REMEDIATED", "VERIFIED_CLOSED", "ESCALATION", "FALSE_POSITIVE", "CLOSED"]

class CustomerCreate(BaseModel):
    name: str
    industry: Optional[str] = None
    tier: str = "standard"
    primary_contact: Optional[str] = None
    email: Optional[str] = None
    slack_channel: Optional[str] = None

class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    tier: Optional[str] = None
    active: Optional[bool] = None

class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    industry: Optional[str]
    tier: str
    primary_contact: Optional[str]
    email: Optional[str]
    slack_channel: Optional[str]
    active: bool
    created_at: datetime

class AssetCreate(BaseModel):
    asset_type: str
    asset_value: str
    criticality: str = "medium"

    @field_validator("asset_value")
    @classmethod
    def validate_asset_value(cls, v, info):
        import re as _re
        v = v.strip()
        if not v or len(v) < 2:
            raise ValueError("Asset value too short")
        if len(v) > 500:
            raise ValueError("Asset value too long (max 500)")
        atype = info.data.get("asset_type", "")
        if atype == "domain":
            if not _re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', v):
                raise ValueError(f"Invalid domain: {v}")
        elif atype == "ip":
            import ipaddress as _ipa
            try:
                _ipa.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address: {v}")
        elif atype == "cidr":
            import ipaddress as _ipa
            try:
                _ipa.ip_network(v, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR: {v}")
        elif atype == "email":
            if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
                raise ValueError(f"Invalid email: {v}")
        return v

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(cls, v):
        valid = {"domain","ip","email","keyword","cidr","org_name","github_org",
                 "subdomain","tech_stack","brand_name","exec_name","cloud_asset","code_repo"}
        if v not in valid:
            raise ValueError(f"Invalid asset_type: {v}. Valid: {', '.join(sorted(valid))}")
        return v

    @field_validator("criticality")
    @classmethod
    def validate_criticality(cls, v):
        valid = {"critical", "high", "medium", "low"}
        if v not in valid:
            raise ValueError(f"Invalid criticality: {v}. Valid: {', '.join(sorted(valid))}")
        return v

class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    customer_id: int
    asset_type: str
    asset_value: str
    criticality: str
    created_at: datetime

class DetectionCreate(BaseModel):
    customer_id: Optional[int] = None
    source: str
    ioc_type: str
    ioc_value: str
    raw_text: Optional[str] = None
    severity: SEVERITY_VALUES = "MEDIUM"
    sla_hours: int = 72
    matched_asset: Optional[str] = None
    confidence: float = 0.5
    metadata_: Optional[dict] = None

class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    customer_id: Optional[int]
    source: str
    ioc_type: str
    ioc_value: str
    raw_text: Optional[str] = None
    severity: SEVERITY_VALUES
    sla_hours: int
    status: STATUS_VALUES
    matched_asset: Optional[str]
    confidence: float
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime]
    created_at: datetime

class DetectionUpdate(BaseModel):
    status: Optional[STATUS_VALUES] = None
    severity: Optional[SEVERITY_VALUES] = None

class EnrichmentCreate(BaseModel):
    detection_id: int
    provider: str
    enrichment_type: Optional[str] = None
    data: dict = {}
    risk_score: Optional[float] = None

class EnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    detection_id: int
    provider: str
    enrichment_type: Optional[str]
    data: dict
    risk_score: Optional[float]
    queried_at: datetime

class RemediationCreate(BaseModel):
    detection_id: int
    action_type: str
    description: Optional[str] = None
    assigned_to: Optional[str] = None

class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    detection_id: int
    action_type: str
    description: Optional[str]
    assigned_to: Optional[str]
    status: str
    created_at: datetime
    completed_at: Optional[datetime]

class DashboardStats(BaseModel):
    total_detections: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    open_count: int
    customers_active: int
    last_collection: Optional[datetime] = None
