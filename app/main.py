import os
import json
import uuid
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.database import init_db, get_connection, log_audit_event
from app.api.routes import router as api_router
from app.fixtures.synthetic_judgments import SYNTHETIC_JUDGMENTS
from app.core.document_processor import extract_metadata_from_text
from app.core.pii_engine import detect_pii_entities
from app.core.legal_role_engine import analyze_legal_role
from app.core.risk_assessment import calculate_privacy_risk
from app.core.redaction_engine import generate_pseudonym_mapping, redact_text_content
from app.core.residual_scanner import scan_residual_leakage
from app.config import (
    UPLOADS_DIR, EXPORTS_DIR, ROLE_DEFAULT_ACTIONS, CATEGORY_DEFAULT_ACTIONS
)

def seed_synthetic_documents():
    """Seeds 3 initial synthetic Indian legal judgments into the database if empty."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM documents")
    count = cursor.fetchone()["cnt"]

    if count == 0:
        print("🌱 Seeding synthetic Indian judgments for immediate evaluation & review...")
        for synth in SYNTHETIC_JUDGMENTS[:3]:
            doc_id = str(uuid.uuid4())
            text = synth["text"]
            file_name = f"judgment_{synth['id']}.txt"
            
            # Save raw file
            file_path = UPLOADS_DIR / file_name
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text)

            meta = extract_metadata_from_text(text)
            now_iso = datetime.utcnow().isoformat() + "Z"

            cursor.execute(
                """
                INSERT INTO documents (
                    id, filename, original_name, file_type, file_size,
                    uploaded_at, status, text_content, page_count,
                    court_name, case_number, case_title, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    doc_id, file_name, f"{synth['title']}.txt", "TXT", len(text),
                    now_iso, "ANALYZED", text, 2,
                    synth["court"], synth["case_number"], synth["title"],
                    json.dumps({"seeded": True, "domain": synth["id"]})
                )
            )

            # Analyze PII
            detected = detect_pii_entities(text)
            entity_records = []
            for d in detected:
                role_res = analyze_legal_role(d["text"], d["category"], text, d["start_char"], d["end_char"])
                pred_role = role_res["predicted_role"]
                cat = d["category"]
                action = ROLE_DEFAULT_ACTIONS.get(pred_role, CATEGORY_DEFAULT_ACTIONS.get(cat, "REDACT"))
                if pred_role in ("VICTIM", "MINOR"):
                    action = "PSEUDONYMIZE"

                ent_id = str(uuid.uuid4())
                record = {
                    "id": ent_id,
                    "document_id": doc_id,
                    "text": d["text"],
                    "category": cat,
                    "start_char": d["start_char"],
                    "end_char": d["end_char"],
                    "confidence": d["confidence"],
                    "predicted_role": pred_role,
                    "role_confidence": role_res["role_confidence"],
                    "role_evidence": role_res["role_evidence"],
                    "action": action,
                    "status": "APPROVED" if pred_role in ("VICTIM", "MINOR") else "PENDING"
                }
                entity_records.append(record)

                cursor.execute(
                    """
                    INSERT INTO pii_entities (
                        id, document_id, text, category, start_char, end_char,
                        page_number, confidence, predicted_role, role_confidence,
                        role_evidence, action, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ent_id, doc_id, d["text"], cat, d["start_char"], d["end_char"],
                        1, d["confidence"], pred_role, role_res["role_confidence"],
                        role_res["role_evidence"], action, record["status"]
                    )
                )

            # Risk assessment
            risk_res = calculate_privacy_risk(entity_records, text)
            risk_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT INTO risk_assessments (
                    id, document_id, overall_score, risk_level, breakdown_json,
                    statutory_alerts_json, recommendations_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    risk_id, doc_id, risk_res["overall_score"], risk_res["risk_level"],
                    json.dumps(risk_res["factors"]), json.dumps(risk_res["statutory_alerts"]),
                    json.dumps(risk_res["recommendations"]), now_iso
                )
            )

            # Auto-redact the first POCSO document so Residual Verification is immediately viewable!
            if synth["id"] == "SYNTH_JUDGMENT_01":
                pseudo_map = generate_pseudonym_mapping(entity_records, style="ROLE_BASED")
                sanitized_text = redact_text_content(text, entity_records, pseudo_map)
                export_txt = EXPORTS_DIR / f"sanitized_{doc_id}.txt"
                with open(export_txt, "w", encoding="utf-8") as f:
                    f.write(sanitized_text)

                redact_id = str(uuid.uuid4())
                cursor.execute(
                    """
                    INSERT INTO redactions (
                        id, document_id, sanitized_text, export_pdf_path,
                        export_docx_path, export_txt_path, mappings_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        redact_id, doc_id, sanitized_text, None, None,
                        str(export_txt), json.dumps(pseudo_map), now_iso
                    )
                )

                # Pre-run residual scan
                scan_res = scan_residual_leakage(sanitized_text, entity_records)
                scan_id = str(uuid.uuid4())
                cursor.execute(
                    """
                    INSERT INTO residual_scans (
                        id, document_id, residual_score, findings_json, scan_summary_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id, doc_id, scan_res["residual_score"],
                        json.dumps(scan_res["findings"]), json.dumps(scan_res["summary"]),
                        now_iso
                    )
                )
                cursor.execute("UPDATE documents SET status = 'VERIFIED' WHERE id = ?", (doc_id,))

            conn.commit()

        log_audit_event(None, "SYSTEM_SEED_INITIALIZED", "SYSTEM", {"seeded_docs_count": 3})
        print(" Seeding complete! 3 sample judgments loaded.")

    conn.close()

# Initialize DB on module load
init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    seed_synthetic_documents()
    yield
    # Shutdown

app = FastAPI(
    title="NyayaShield AI",
    description="Intelligent Detection, Risk Assessment, and Privacy-Preserving Redaction of PII in Indian Legal Judgments",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://nyayashield-frontend.vercel.app",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(api_router)

@app.get("/")
def root():
    return {
        "title": "NyayaShield AI",
        "description": "Intelligent Detection, Risk Assessment, and Privacy-Preserving Redaction of PII in Indian Legal Judgments",
        "status": "operational",
        "docs": "/docs",
        "health": "/api/health"
    }
