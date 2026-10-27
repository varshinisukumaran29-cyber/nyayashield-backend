import pytest
from fastapi.testclient import TestClient
from app.main import app, init_db, seed_synthetic_documents

@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    seed_synthetic_documents()

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "NyayaShield AI" in data["service"]

def test_list_and_get_documents():
    with TestClient(app) as client:
        response = client.get("/api/documents")
        assert response.status_code == 200
        docs = response.json()
        assert isinstance(docs, list)
        assert len(docs) >= 1  # Should have seeded docs

        doc_id = docs[0]["id"]
        detail_res = client.get(f"/api/documents/{doc_id}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == doc_id
        assert "text_content" in detail

def test_evaluation_benchmark_endpoint():
    with TestClient(app) as client:
        response = client.post("/api/evaluation/run")
        assert response.status_code == 200
        bench = response.json()
        assert "baselines" in bench
        assert "NYAYASHIELD_HYBRID" in bench["baselines"]
        assert "REGEX_ONLY" in bench["baselines"]
        assert "GENERAL_NER" in bench["baselines"]
        assert bench["baselines"]["NYAYASHIELD_HYBRID"]["f1_score"] > bench["baselines"]["REGEX_ONLY"]["f1_score"]

def test_audit_trail_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/audit")
        assert response.status_code == 200
        logs = response.json()
        assert isinstance(logs, list)
        assert len(logs) >= 1
        assert "tamper_hash" in logs[0]
