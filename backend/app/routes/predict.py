import io
import csv
from typing import List
from fastapi import APIRouter, File, UploadFile, HTTPException
import pandas as pd

from app.ml.model_loader import model_manager
from app.schemas import (
    SingleDomainRequest,
    PredictionResult,
    CsvAnalysisResponse,
    BatchAnalysisSummary,
    SuspiciousDomainItem
)

router = APIRouter(prefix="/api", tags=["Prediction"])

@router.post("/predict", response_model=PredictionResult)
def predict_single_domain(req: SingleDomainRequest):
    """Classifies a single DNS request using the trained ML model."""
    if not req.domain or not req.domain.strip():
        raise HTTPException(status_code=400, detail="Domain string cannot be empty.")
    
    return model_manager.predict_record(
        domain=req.domain,
        query_type=req.query_type or "A",
        response_size=req.response_size or 140.0,
        ttl=req.ttl or 300.0
    )

@router.post("/predict/csv", response_model=CsvAnalysisResponse)
async def predict_csv(file: UploadFile = File(...)):
    """
    Parses an uploaded DNS traffic CSV, extracts 10 features per row,
    and returns comprehensive ML predictions, summary statistics,
    and ranked threat domains.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a .csv file.")

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded CSV file is empty.")

    # Try UTF-8 then fallback to latin-1
    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError:
        text = contents.decode("latin-1")

    # Read CSV via pandas
    try:
        df = pd.read_csv(io.StringIO(text))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV format: {str(e)}")

    if df.empty:
        raise HTTPException(status_code=400, detail="CSV contains no records.")

    # Normalize column names
    col_map = {c.strip().lower(): c for c in df.columns}
    if "domain" not in col_map:
        raise HTTPException(
            status_code=400,
            detail="CSV must contain a 'domain' column."
        )

    domain_col = col_map["domain"]
    query_type_col = col_map.get("query_type")
    response_size_col = col_map.get("response_size")
    ttl_col = col_map.get("ttl")

    records = []
    suspicious_items = []
    confidences = []

    for _, row in df.iterrows():
        domain_val = str(row[domain_col]).strip()
        if not domain_val or domain_val == "nan":
            continue

        qtype = str(row[query_type_col]).strip() if query_type_col else "A"
        
        try:
            rsize = float(row[response_size_col]) if response_size_col else 140.0
        except (ValueError, TypeError):
            rsize = 140.0

        try:
            ttl_val = float(row[ttl_col]) if ttl_col else 300.0
        except (ValueError, TypeError):
            ttl_val = 300.0

        res = model_manager.predict_record(
            domain=domain_val,
            query_type=qtype,
            response_size=rsize,
            ttl=ttl_val
        )
        records.append(res)
        confidences.append(res["confidence"])

        if res["prediction"] == "DNS TUNNELING":
            suspicious_items.append(
                SuspiciousDomainItem(
                    domain=res["domain"],
                    threat_score=res["threat_score"],
                    threat_percentage=res["threat_percentage"],
                    risk_level=res["risk_level"],
                    reasons=res["reasons"]
                )
            )

    if not records:
        raise HTTPException(status_code=400, detail="No valid domains found in CSV.")

    total_records = len(records)
    suspicious_count = len(suspicious_items)
    normal_count = total_records - suspicious_count
    detection_rate_pct = round((suspicious_count / total_records) * 100, 1)
    avg_confidence = round(sum(confidences) / len(confidences), 1) if confidences else 95.0
    overall_status = "DNS TUNNELING DETECTED" if suspicious_count > 0 else "NORMAL DNS TRAFFIC"

    # Sort suspicious domains by threat score descending
    suspicious_items.sort(key=lambda x: x.threat_score, reverse=True)

    summary = BatchAnalysisSummary(
        total_records=total_records,
        normal_count=normal_count,
        suspicious_count=suspicious_count,
        detection_rate_pct=detection_rate_pct,
        overall_status=overall_status,
        avg_confidence=avg_confidence
    )

    first_record = records[0] if records else None

    return CsvAnalysisResponse(
        summary=summary,
        first_record_features=first_record,
        suspicious_domains=suspicious_items,
        records=records
    )
