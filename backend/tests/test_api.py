import os
import sys
from pathlib import Path
from starlette.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "DNS-TunnelGuard"
    print("[PASS] GET / passed")

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    print("[PASS] GET /api/health passed")

def test_model_info():
    response = client.get("/api/model/info")
    assert response.status_code == 200
    data = response.json()
    assert "features" in data
    assert len(data["features"]) == 10
    print("[PASS] GET /api/model/info passed")

def test_predict_single_benign():
    response = client.post("/api/predict", json={
        "domain": "google.com",
        "query_type": "A",
        "response_size": 120,
        "ttl": 300
    })
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "NORMAL"
    assert data["threat_score"] == 0.0
    print("[PASS] POST /api/predict (benign) passed")

def test_predict_single_tunneling():
    response = client.post("/api/predict", json={
        "domain": "jx8k2m9q7x.example.org",
        "query_type": "A",
        "response_size": 610,
        "ttl": 30
    })
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "DNS TUNNELING"
    assert data["risk_level"] in ["MEDIUM", "HIGH"]
    print("[PASS] POST /api/predict (tunneling) passed")

def test_predict_csv():
    csv_path = BACKEND_DIR.parent / "frontend" / "public" / "dns_traffic_demo.csv"
    with open(csv_path, "rb") as f:
        response = client.post(
            "/api/predict/csv",
            files={"file": ("dns_traffic_demo.csv", f, "text/csv")}
        )
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["total_records"] == 10
    assert data["summary"]["suspicious_count"] == 4
    assert data["summary"]["normal_count"] == 6
    assert data["summary"]["overall_status"] == "DNS TUNNELING DETECTED"
    assert len(data["suspicious_domains"]) == 4
    print("[PASS] POST /api/predict/csv passed (10 records: 6 normal, 4 tunneling flagged)")

if __name__ == "__main__":
    test_root()
    test_health()
    test_model_info()
    test_predict_single_benign()
    test_predict_single_tunneling()
    test_predict_csv()
    print("\nALL BACKEND API TESTS PASSED SUCCESSFULLY!")

