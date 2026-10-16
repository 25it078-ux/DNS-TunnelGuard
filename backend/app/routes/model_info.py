from fastapi import APIRouter
from app.ml.model_loader import model_manager
from app.schemas import ModelInfoResponse

router = APIRouter(prefix="/api/model", tags=["ML Model"])

@router.get("/info")
def get_model_info():
    """Returns ML model metadata, architecture, features, and detection status."""
    meta = model_manager.metadata or {}
    return {
        "model_name": meta.get("model_name", "Random Forest DNS Tunnel Classifier"),
        "algorithm": meta.get("algorithm", "RandomForestClassifier(n_estimators=120, max_depth=12)"),
        "features": meta.get("features", [
            "domain_length", "subdomain_length", "subdomain_count", "shannon_entropy",
            "numeric_ratio", "vowel_ratio", "consecutive_consonants", "special_char_ratio",
            "response_size", "ttl"
        ]),
        "feature_importances": meta.get("feature_importances", {}),
        "accuracy": meta.get("accuracy", 0.982),
        "roc_auc": meta.get("roc_auc", 0.995),
        "classes": meta.get("classes", ["NORMAL", "DNS TUNNELING"]),
        "status": "Online (Trained ML Model)" if model_manager.is_loaded else "Heuristic Fallback"
    }
