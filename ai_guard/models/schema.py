from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Union

class Category(str, Enum):
    CODE_EXECUTION = "code_execution"
    PROMPT_INJECTION = "prompt_injection"
    SUPPLY_CHAIN = "supply_chain"
    FILESYSTEM_ACCESS = "filesystem_access"
    NETWORK_ACCESS = "network_access"

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Finding(BaseModel):
    rule_id: str
    category: Category
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    description: str
    evidence: Optional[str] = None
    confidence: float = 1.0

class Report(BaseModel):
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_level: str
    recommendation: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    summary: str
    categories: Dict[str, float]
    normalized_contributions: Dict[str, float]
    top_findings: List[Finding]
    features: Dict[str, Union[bool, int]] = {}
    capabilities: List[str]
    findings: List[Finding]
