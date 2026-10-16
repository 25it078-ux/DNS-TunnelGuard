from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class SingleDomainRequest(BaseModel):
    domain: str = Field(..., example="data-transfer.example.net")
    query_type: Optional[str] = Field("A", example="A")
    response_size: Optional[float] = Field(140.0, example=520.0)
    ttl: Optional[float] = Field(300.0, example=45.0)

class DisplayMetrics(BaseModel):
    queryLength: int
    domainLength: int
    subdomainCount: int
    entropy: float
    numericRatio: float
    vowelRatio: float
    responseSize: float
    ttl: float

class PredictionResult(BaseModel):
    domain: str
    query_type: str
    prediction: str
    threat_score: float
    threat_percentage: float
    confidence: float
    risk_level: str
    reasons: List[str]
    display_metrics: DisplayMetrics
    raw_features: Dict[str, Any]

class BatchAnalysisSummary(BaseModel):
    total_records: int
    normal_count: int
    suspicious_count: int
    detection_rate_pct: float
    overall_status: str
    avg_confidence: float

class SuspiciousDomainItem(BaseModel):
    domain: str
    threat_score: float
    threat_percentage: float
    risk_level: str
    reasons: List[str]

class CsvAnalysisResponse(BaseModel):
    summary: BatchAnalysisSummary
    first_record_features: Optional[PredictionResult]
    suspicious_domains: List[SuspiciousDomainItem]
    records: List[PredictionResult]

class ModelInfoResponse(BaseModel):
    model_name: str
    algorithm: str
    features: List[str]
    feature_importances: Dict[str, float]
    accuracy: float
    roc_auc: float
    classes: List[str]
    status: str
