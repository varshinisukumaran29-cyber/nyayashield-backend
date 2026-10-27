from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class PIIEntityBase(BaseModel):
    text: str
    category: str
    start_char: int
    end_char: int
    page_number: int = 1
    confidence: float
    predicted_role: str
    role_confidence: float
    role_evidence: Optional[str] = None
    action: str  # REDACT, MASK, PSEUDONYMIZE, REVIEW
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, MODIFIED
    pseudonym: Optional[str] = None
    reviewer_notes: Optional[str] = None

class PIIEntityResponse(PIIEntityBase):
    id: str
    document_id: str
    is_manual_addition: bool = False

class PIIEntityUpdate(BaseModel):
    category: Optional[str] = None
    predicted_role: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    pseudonym: Optional[str] = None
    reviewer_notes: Optional[str] = None

class PIIEntityManualCreate(BaseModel):
    text: str
    category: str
    start_char: int
    end_char: int
    page_number: int = 1
    predicted_role: str = "GENERAL_INDIVIDUAL"
    action: str = "REDACT"
    reviewer_notes: Optional[str] = None

class DocumentListItem(BaseModel):
    id: str
    filename: str
    original_name: str
    file_type: str
    file_size: int
    uploaded_at: str
    status: str
    page_count: int
    court_name: Optional[str] = None
    case_number: Optional[str] = None
    case_title: Optional[str] = None
    pii_count: int = 0
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None

class DocumentDetailResponse(DocumentListItem):
    text_content: str
    entities: List[PIIEntityResponse] = []
    risk_assessment: Optional[Dict[str, Any]] = None
    redaction: Optional[Dict[str, Any]] = None
    residual_scan: Optional[Dict[str, Any]] = None

class RiskFactorBreakdown(BaseModel):
    factor: str
    category: str
    weight: float
    impact_score: float
    description: str

class StatutoryAlert(BaseModel):
    statute: str
    section: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    rationale: str
    guidance: str

class RiskAssessmentResponse(BaseModel):
    document_id: str
    overall_score: float
    risk_level: str  # LOW, MODERATE, HIGH, CRITICAL
    factors: List[RiskFactorBreakdown]
    statutory_alerts: List[StatutoryAlert]
    recommendations: List[str]
    disclaimer: str

class RedactionApplyRequest(BaseModel):
    mask_char: str = "*"
    pseudonym_style: str = "ROLE_BASED"  # ROLE_BASED or ALPHABETIC or NUMBERED
    preserve_citations: bool = True
    preserve_court_officers: bool = False

class RedactionResponse(BaseModel):
    document_id: str
    sanitized_text: str
    redacted_entity_count: int
    export_formats: Dict[str, str]
    message: str

class ResidualFinding(BaseModel):
    token: str
    suspected_category: str
    context_snippet: str
    char_offset: int
    confidence: float
    flag_reason: str

class ResidualScanResponse(BaseModel):
    document_id: str
    residual_score: float  # 0.0 to 100.0 (0 means clean)
    cleanliness_rate: float  # e.g. 98.5%
    findings: List[ResidualFinding]
    summary: Dict[str, Any]
    uncertain_flag_count: int
    disclaimer: str

class BenchmarkMetrics(BaseModel):
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    false_positives: int
    false_negatives: int
    redaction_coverage_pct: float
    residual_leakage_pct: float
    latency_ms: float
    entity_metrics: Dict[str, Dict[str, float]]

class EvaluationRunResponse(BaseModel):
    id: str
    benchmark_name: str
    timestamp: str
    baselines: Dict[str, BenchmarkMetrics]
    dataset_summary: Dict[str, Any]

class AuditLogItem(BaseModel):
    id: int
    document_id: Optional[str]
    timestamp: str
    event_type: str
    actor: str
    details: Dict[str, Any]
    tamper_hash: str
