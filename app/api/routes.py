import os
import uuid
import json
import shutil
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from datetime import datetime

from app.config import (
    UPLOADS_DIR, EXPORTS_DIR, ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH,
    ROLE_DEFAULT_ACTIONS, CATEGORY_DEFAULT_ACTIONS, LEGAL_DISCLAIMER
)
from app.database import get_connection, log_audit_event
from app.models.schemas import (
    DocumentListItem, DocumentDetailResponse, PIIEntityResponse,
    PIIEntityUpdate, PIIEntityManualCreate, RiskAssessmentResponse,
    RedactionApplyRequest, RedactionResponse, ResidualScanResponse,
    EvaluationRunResponse, AuditLogItem
)
from app.core.document_processor import process_pdf, process_docx, process_txt
from app.core.pii_engine import detect_pii_entities
from app.core.legal_role_engine import analyze_legal_role
from app.core.risk_assessment import calculate_privacy_risk
from app.core.redaction_engine import (
    generate_pseudonym_mapping, redact_text_content,
    redact_pdf_document, redact_docx_document
)
from app.core.residual_scanner import scan_residual_leakage
from app.core.evaluation_lab import execute_full_benchmark

router = APIRouter(prefix="/api", tags=["NyayaShield API"])

# 1. Health Check
@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NyayaShield AI",
        "version": "1.0.0",
        "engine": "Context-Aware Indian Legal Redaction Pipeline",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

# 2. Document Upload & Text Extraction
@router.post("/documents/upload", response_model=Dict[str, Any])
async def upload_document(file: UploadFile = File(...)):
    filename = file.filename or "judgment.txt"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Supported: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    doc_id = str(uuid.uuid4())
    save_path = UPLOADS_DIR / f"{doc_id}{ext}"

    # Read and save file safely
    content = await file.read()
    if len(content) > MAX_CONTENT_LENGTH:
        raise HTTPException(status_code=400, detail="File size exceeds maximum permitted limit (20MB).")

    with open(save_path, "wb") as f:
        f.write(content)

    file_size = len(content)

    # Process extraction
    try:
        if ext == ".pdf":
            extracted = process_pdf(str(save_path))
        elif ext == ".docx":
            extracted = process_docx(str(save_path))
        else:
            extracted = process_txt(str(save_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text extraction failed: {str(e)}")

    now_iso = datetime.utcnow().isoformat() + "Z"
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO documents (
            id, filename, original_name, file_type, file_size,
            uploaded_at, status, text_content, page_count,
            court_name, case_number, case_title, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            doc_id, f"{doc_id}{ext}", filename, ext[1:].upper(), file_size,
            now_iso, "EXTRACTED", extracted["text_content"], extracted["page_count"],
            extracted.get("court_name"), extracted.get("case_number"), extracted.get("case_title"),
            json.dumps({"is_scanned": extracted.get("is_scanned", False), "ratio": extracted.get("scanned_page_ratio", 0.0)})
        )
    )
    conn.commit()
    conn.close()

    log_audit_event(doc_id, "DOCUMENT_UPLOAD", "USER", {
        "filename": filename,
        "file_type": ext,
        "file_size": file_size,
        "page_count": extracted["page_count"]
    })

    return {
        "id": doc_id,
        "filename": filename,
        "file_type": ext[1:].upper(),
        "file_size": file_size,
        "page_count": extracted["page_count"],
        "court_name": extracted.get("court_name"),
        "case_number": extracted.get("case_number"),
        "case_title": extracted.get("case_title"),
        "is_scanned": extracted.get("is_scanned", False),
        "status": "EXTRACTED"
    }

# 3. List Documents
@router.get("/documents", response_model=List[DocumentListItem])
def list_documents():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.id, d.filename, d.original_name, d.file_type, d.file_size,
               d.uploaded_at, d.status, d.page_count, d.court_name, d.case_number, d.case_title,
               COUNT(p.id) as pii_count,
               r.risk_level, r.overall_score as risk_score
        FROM documents d
        LEFT JOIN pii_entities p ON d.id = p.document_id
        LEFT JOIN risk_assessments r ON d.id = r.document_id
        GROUP BY d.id
        ORDER BY d.uploaded_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    res = []
    for r in rows:
        res.append(DocumentListItem(
            id=r["id"],
            filename=r["filename"],
            original_name=r["original_name"],
            file_type=r["file_type"],
            file_size=r["file_size"],
            uploaded_at=r["uploaded_at"],
            status=r["status"],
            page_count=r["page_count"],
            court_name=r["court_name"],
            case_number=r["case_number"],
            case_title=r["case_title"],
            pii_count=r["pii_count"] or 0,
            risk_level=r["risk_level"],
            risk_score=r["risk_score"]
        ))
    return res

# 4. Get Document Details
@router.get("/documents/{doc_id}", response_model=DocumentDetailResponse)
def get_document_details(doc_id: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc_row = cursor.fetchone()
    if not doc_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    # Fetch PII Entities
    cursor.execute("SELECT * FROM pii_entities WHERE document_id = ? ORDER BY start_char ASC", (doc_id,))
    entity_rows = cursor.fetchall()
    entities = []
    for e in entity_rows:
        entities.append(PIIEntityResponse(
            id=e["id"],
            document_id=e["document_id"],
            text=e["text"],
            category=e["category"],
            start_char=e["start_char"],
            end_char=e["end_char"],
            page_number=e["page_number"],
            confidence=e["confidence"],
            predicted_role=e["predicted_role"],
            role_confidence=e["role_confidence"],
            role_evidence=e["role_evidence"],
            action=e["action"],
            status=e["status"],
            pseudonym=e["pseudonym"],
            reviewer_notes=e["reviewer_notes"],
            is_manual_addition=bool(e["is_manual_addition"])
        ))

    # Fetch Risk Assessment
    cursor.execute("SELECT * FROM risk_assessments WHERE document_id = ?", (doc_id,))
    risk_row = cursor.fetchone()
    risk_dict = None
    if risk_row:
        risk_dict = {
            "overall_score": risk_row["overall_score"],
            "risk_level": risk_row["risk_level"],
            "factors": json.loads(risk_row["breakdown_json"]),
            "statutory_alerts": json.loads(risk_row["statutory_alerts_json"]),
            "recommendations": json.loads(risk_row["recommendations_json"]),
            "disclaimer": LEGAL_DISCLAIMER
        }

    # Fetch Redaction
    cursor.execute("SELECT * FROM redactions WHERE document_id = ?", (doc_id,))
    redact_row = cursor.fetchone()
    redact_dict = None
    if redact_row:
        redact_dict = {
            "sanitized_text": redact_row["sanitized_text"],
            "export_pdf_path": redact_row["export_pdf_path"],
            "export_docx_path": redact_row["export_docx_path"],
            "export_txt_path": redact_row["export_txt_path"],
            "created_at": redact_row["created_at"]
        }

    # Fetch Residual Scan
    cursor.execute("SELECT * FROM residual_scans WHERE document_id = ?", (doc_id,))
    scan_row = cursor.fetchone()
    scan_dict = None
    if scan_row:
        scan_dict = {
            "residual_score": scan_row["residual_score"],
            "findings": json.loads(scan_row["findings_json"]),
            "summary": json.loads(scan_row["scan_summary_json"]),
            "disclaimer": LEGAL_DISCLAIMER
        }

    conn.close()

    return DocumentDetailResponse(
        id=doc_row["id"],
        filename=doc_row["filename"],
        original_name=doc_row["original_name"],
        file_type=doc_row["file_type"],
        file_size=doc_row["file_size"],
        uploaded_at=doc_row["uploaded_at"],
        status=doc_row["status"],
        page_count=doc_row["page_count"],
        court_name=doc_row["court_name"],
        case_number=doc_row["case_number"],
        case_title=doc_row["case_title"],
        pii_count=len(entities),
        risk_level=risk_dict["risk_level"] if risk_dict else None,
        risk_score=risk_dict["overall_score"] if risk_dict else None,
        text_content=doc_row["text_content"],
        entities=entities,
        risk_assessment=risk_dict,
        redaction=redact_dict,
        residual_scan=scan_dict
    )

# 5. Analyze PII & Contextual Legal Roles
@router.post("/documents/{doc_id}/analyze")
def analyze_document_pii(doc_id: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT text_content, original_name FROM documents WHERE id = ?", (doc_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    text = row["text_content"]
    detected = detect_pii_entities(text)

    # Clean existing entities for this doc
    cursor.execute("DELETE FROM pii_entities WHERE document_id = ? AND is_manual_addition = 0", (doc_id,))

    entity_records = []
    for d in detected:
        role_res = analyze_legal_role(d["text"], d["category"], text, d["start_char"], d["end_char"])
        
        # Decide action based on role and category policy
        pred_role = role_res["predicted_role"]
        cat = d["category"]
        action = ROLE_DEFAULT_ACTIONS.get(pred_role, CATEGORY_DEFAULT_ACTIONS.get(cat, "REDACT"))

        # High sensitivity: if victim/minor, set PSEUDONYMIZE
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
            "status": "PENDING"
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
                role_res["role_evidence"], action, "PENDING"
            )
        )

    # Compute Risk Assessment
    risk_res = calculate_privacy_risk(entity_records, text, is_post_redaction=False)
    risk_id = str(uuid.uuid4())
    cursor.execute("DELETE FROM risk_assessments WHERE document_id = ?", (doc_id,))
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
            json.dumps(risk_res["recommendations"]), datetime.utcnow().isoformat() + "Z"
        )
    )

    cursor.execute("UPDATE documents SET status = 'ANALYZED' WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    log_audit_event(doc_id, "PII_ANALYSIS_COMPLETED", "SYSTEM_ENGINE", {
        "detected_entities_count": len(entity_records),
        "risk_score": risk_res["overall_score"],
        "risk_level": risk_res["risk_level"]
    })

    return {
        "document_id": doc_id,
        "entities_count": len(entity_records),
        "risk_score": risk_res["overall_score"],
        "risk_level": risk_res["risk_level"],
        "message": f"Successfully analyzed {len(entity_records)} PII entities."
    }

# 6. Update Entity (Workbench Human Review: Approve, Reject, Edit Action, Edit Role)
@router.patch("/entities/{entity_id}", response_model=PIIEntityResponse)
def update_entity(entity_id: str, update_data: PIIEntityUpdate):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM pii_entities WHERE id = ?", (entity_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Entity not found")

    new_cat = update_data.category or row["category"]
    new_role = update_data.predicted_role or row["predicted_role"]
    new_action = update_data.action or row["action"]
    new_status = update_data.status or row["status"]
    new_pseudo = update_data.pseudonym if update_data.pseudonym is not None else row["pseudonym"]
    new_notes = update_data.reviewer_notes if update_data.reviewer_notes is not None else row["reviewer_notes"]

    cursor.execute(
        """
        UPDATE pii_entities
        SET category = ?, predicted_role = ?, action = ?, status = ?,
            pseudonym = ?, reviewer_notes = ?
        WHERE id = ?
        """,
        (new_cat, new_role, new_action, new_status, new_pseudo, new_notes, entity_id)
    )
    conn.commit()

    cursor.execute("SELECT * FROM pii_entities WHERE id = ?", (entity_id,))
    updated_row = cursor.fetchone()
    conn.close()

    log_audit_event(row["document_id"], "ENTITY_REVIEW_UPDATE", "HUMAN_REVIEWER", {
        "entity_id": entity_id,
        "previous_status": row["status"],
        "new_status": new_status,
        "action": new_action,
        "notes": new_notes
    })

    return PIIEntityResponse(
        id=updated_row["id"],
        document_id=updated_row["document_id"],
        text=updated_row["text"],
        category=updated_row["category"],
        start_char=updated_row["start_char"],
        end_char=updated_row["end_char"],
        page_number=updated_row["page_number"],
        confidence=updated_row["confidence"],
        predicted_role=updated_row["predicted_role"],
        role_confidence=updated_row["role_confidence"],
        role_evidence=updated_row["role_evidence"],
        action=updated_row["action"],
        status=updated_row["status"],
        pseudonym=updated_row["pseudonym"],
        reviewer_notes=updated_row["reviewer_notes"],
        is_manual_addition=bool(updated_row["is_manual_addition"])
    )

# 7. Add Manual Entity in Review Workbench
@router.post("/documents/{doc_id}/entities", response_model=PIIEntityResponse)
def add_manual_entity(doc_id: str, payload: PIIEntityManualCreate):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM documents WHERE id = ?", (doc_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    ent_id = str(uuid.uuid4())
    cursor.execute(
        """
        INSERT INTO pii_entities (
            id, document_id, text, category, start_char, end_char,
            page_number, confidence, predicted_role, role_confidence,
            role_evidence, action, status, is_manual_addition, reviewer_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            ent_id, doc_id, payload.text, payload.category, payload.start_char, payload.end_char,
            payload.page_number, 1.0, payload.predicted_role, 1.0,
            "Manually annotated by human legal reviewer", payload.action, "APPROVED", payload.reviewer_notes
        )
    )
    conn.commit()

    cursor.execute("SELECT * FROM pii_entities WHERE id = ?", (ent_id,))
    row = cursor.fetchone()
    conn.close()

    log_audit_event(doc_id, "MANUAL_ENTITY_ADDED", "HUMAN_REVIEWER", {
        "text": payload.text,
        "category": payload.category,
        "action": payload.action
    })

    return PIIEntityResponse(
        id=row["id"],
        document_id=row["document_id"],
        text=row["text"],
        category=row["category"],
        start_char=row["start_char"],
        end_char=row["end_char"],
        page_number=row["page_number"],
        confidence=row["confidence"],
        predicted_role=row["predicted_role"],
        role_confidence=row["role_confidence"],
        role_evidence=row["role_evidence"],
        action=row["action"],
        status=row["status"],
        pseudonym=row["pseudonym"],
        reviewer_notes=row["reviewer_notes"],
        is_manual_addition=True
    )

# 8. Apply Redaction & Generate Sanitized Outputs
@router.post("/documents/{doc_id}/redact", response_model=RedactionResponse)
def apply_document_redaction(doc_id: str, req: RedactionApplyRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc_row = cursor.fetchone()
    if not doc_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    cursor.execute("SELECT * FROM pii_entities WHERE document_id = ?", (doc_id,))
    entity_rows = cursor.fetchall()
    entities = [dict(r) for r in entity_rows]

    # Generate document-scoped pseudonym mapping
    pseudonym_mapping = generate_pseudonym_mapping(entities, style=req.pseudonym_style)

    # Filter entities that should be redacted (status is not REJECTED)
    active_entities = [e for e in entities if e.get("status") != "REJECTED"]

    # 1. Redact text content
    sanitized_text = redact_text_content(
        doc_row["text_content"], active_entities, pseudonym_mapping, mask_char=req.mask_char
    )

    # 2. Export TXT
    export_txt_name = f"sanitized_{doc_id}.txt"
    export_txt_path = EXPORTS_DIR / export_txt_name
    with open(export_txt_path, "w", encoding="utf-8") as f:
        f.write(sanitized_text)

    # 3. Export PDF if source was PDF
    source_ext = doc_row["file_type"].lower()
    source_file_path = UPLOADS_DIR / doc_row["filename"]
    export_pdf_path = None
    export_docx_path = None

    if source_ext == "pdf" and os.path.exists(source_file_path):
        out_pdf_name = f"sanitized_{doc_id}.pdf"
        out_pdf_path = EXPORTS_DIR / out_pdf_name
        pdf_ok = redact_pdf_document(str(source_file_path), str(out_pdf_path), active_entities, pseudonym_mapping)
        if pdf_ok:
            export_pdf_path = str(out_pdf_path)

    elif source_ext == "docx" and os.path.exists(source_file_path):
        out_docx_name = f"sanitized_{doc_id}.docx"
        out_docx_path = EXPORTS_DIR / out_docx_name
        docx_ok = redact_docx_document(str(source_file_path), str(out_docx_path), active_entities, pseudonym_mapping, req.mask_char)
        if docx_ok:
            export_docx_path = str(out_docx_path)

    redact_id = str(uuid.uuid4())
    cursor.execute("DELETE FROM redactions WHERE document_id = ?", (doc_id,))
    cursor.execute(
        """
        INSERT INTO redactions (
            id, document_id, sanitized_text, export_pdf_path,
            export_docx_path, export_txt_path, mappings_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            redact_id, doc_id, sanitized_text, export_pdf_path,
            export_docx_path, str(export_txt_path), json.dumps(pseudonym_mapping),
            datetime.utcnow().isoformat() + "Z"
        )
    )

    cursor.execute("UPDATE documents SET status = 'REDACTED' WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    log_audit_event(doc_id, "REDACTION_APPLIED", "HUMAN_REVIEWER", {
        "redacted_entities_count": len(active_entities),
        "pseudonym_style": req.pseudonym_style,
        "mask_char": req.mask_char,
        "has_pdf": bool(export_pdf_path),
        "has_docx": bool(export_docx_path)
    })

    return RedactionResponse(
        document_id=doc_id,
        sanitized_text=sanitized_text,
        redacted_entity_count=len(active_entities),
        export_formats={
            "txt": f"/api/documents/{doc_id}/export/txt",
            "pdf": f"/api/documents/{doc_id}/export/pdf" if export_pdf_path else "",
            "docx": f"/api/documents/{doc_id}/export/docx" if export_docx_path else "",
        },
        message="Document successfully redacted and sanitized."
    )

# 9. Verify Residual PII Leakage (2nd Pass Independent Scan)
@router.post("/documents/{doc_id}/verify", response_model=ResidualScanResponse)
def verify_residual_leakage(doc_id: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT sanitized_text FROM redactions WHERE document_id = ?", (doc_id,))
    redact_row = cursor.fetchone()
    if not redact_row:
        conn.close()
        raise HTTPException(status_code=400, detail="Document must be redacted before residual leakage scanning.")

    cursor.execute("SELECT text, category, action, status FROM pii_entities WHERE document_id = ?", (doc_id,))
    entities = [dict(r) for r in cursor.fetchall()]

    sanitized_text = redact_row["sanitized_text"]
    scan_res = scan_residual_leakage(sanitized_text, entities)

    scan_id = str(uuid.uuid4())
    cursor.execute("DELETE FROM residual_scans WHERE document_id = ?", (doc_id,))
    cursor.execute(
        """
        INSERT INTO residual_scans (
            id, document_id, residual_score, findings_json, scan_summary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, doc_id, scan_res["residual_score"],
            json.dumps(scan_res["findings"]), json.dumps(scan_res["summary"]),
            datetime.utcnow().isoformat() + "Z"
        )
    )

    cursor.execute("UPDATE documents SET status = 'VERIFIED' WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    log_audit_event(doc_id, "RESIDUAL_LEAKAGE_SCAN", "SYSTEM_ENGINE", {
        "residual_score": scan_res["residual_score"],
        "cleanliness_rate": scan_res["cleanliness_rate"],
        "findings_count": len(scan_res["findings"])
    })

    return ResidualScanResponse(
        document_id=doc_id,
        residual_score=scan_res["residual_score"],
        cleanliness_rate=scan_res["cleanliness_rate"],
        findings=scan_res["findings"],
        summary=scan_res["summary"],
        uncertain_flag_count=scan_res["uncertain_flag_count"],
        disclaimer=scan_res["disclaimer"]
    )

# 10. Export Sanitized Document
@router.get("/documents/{doc_id}/export/{format}")
def export_sanitized_document(doc_id: str, format: str):
    format_lower = format.lower()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT original_name FROM documents WHERE id = ?", (doc_id,))
    doc_row = cursor.fetchone()
    if not doc_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    cursor.execute("SELECT * FROM redactions WHERE document_id = ?", (doc_id,))
    redact_row = cursor.fetchone()
    conn.close()

    if not redact_row:
        raise HTTPException(status_code=400, detail="Sanitized output not yet generated. Please apply redaction first.")

    base_name = os.path.splitext(doc_row["original_name"])[0]

    if format_lower == "txt":
        txt_path = redact_row["export_txt_path"]
        if not txt_path or not os.path.exists(txt_path):
            raise HTTPException(status_code=404, detail="Sanitized TXT file missing")
        return FileResponse(txt_path, media_type="text/plain", filename=f"{base_name}_sanitized.txt")

    elif format_lower == "pdf":
        pdf_path = redact_row["export_pdf_path"]
        if not pdf_path or not os.path.exists(pdf_path):
            raise HTTPException(status_code=404, detail="Sanitized PDF not available for this document")
        return FileResponse(pdf_path, media_type="application/pdf", filename=f"{base_name}_sanitized.pdf")

    elif format_lower == "docx":
        docx_path = redact_row["export_docx_path"]
        if not docx_path or not os.path.exists(docx_path):
            raise HTTPException(status_code=404, detail="Sanitized DOCX not available for this document")
        return FileResponse(
            docx_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=f"{base_name}_sanitized.docx"
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported export format. Supported: txt, pdf, docx")

# 11. Research & Evaluation Benchmark Lab
@router.post("/evaluation/run", response_model=EvaluationRunResponse)
def run_evaluation_benchmark():
    benchmark_res = execute_full_benchmark()
    eval_id = str(uuid.uuid4())

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO evaluation_benchmarks (
            id, benchmark_name, timestamp, regex_metrics_json,
            ner_metrics_json, nyayashield_metrics_json, dataset_summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            eval_id, benchmark_res["benchmark_name"], benchmark_res["timestamp"],
            json.dumps(benchmark_res["baselines"]["REGEX_ONLY"]),
            json.dumps(benchmark_res["baselines"]["GENERAL_NER"]),
            json.dumps(benchmark_res["baselines"]["NYAYASHIELD_HYBRID"]),
            json.dumps(benchmark_res["dataset_summary"])
        )
    )
    conn.commit()
    conn.close()

    log_audit_event(None, "BENCHMARK_EVALUATION_EXECUTED", "RESEARCH_LAB", {
        "benchmark_id": eval_id,
        "nyayashield_f1": benchmark_res["baselines"]["NYAYASHIELD_HYBRID"]["f1_score"],
        "regex_f1": benchmark_res["baselines"]["REGEX_ONLY"]["f1_score"]
    })

    return EvaluationRunResponse(
        id=eval_id,
        benchmark_name=benchmark_res["benchmark_name"],
        timestamp=benchmark_res["timestamp"],
        baselines=benchmark_res["baselines"],
        dataset_summary=benchmark_res["dataset_summary"]
    )

@router.get("/evaluation/latest")
def get_latest_evaluation():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evaluation_benchmarks ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if not row:
        # Run automatically on first request
        return run_evaluation_benchmark()

    return {
        "id": row["id"],
        "benchmark_name": row["benchmark_name"],
        "timestamp": row["timestamp"],
        "baselines": {
            "REGEX_ONLY": json.loads(row["regex_metrics_json"]),
            "GENERAL_NER": json.loads(row["ner_metrics_json"]),
            "NYAYASHIELD_HYBRID": json.loads(row["nyayashield_metrics_json"]),
        },
        "dataset_summary": json.loads(row["dataset_summary_json"])
    }

# 12. Audit Trail
@router.get("/audit", response_model=List[AuditLogItem])
def get_audit_trail(doc_id: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    if doc_id:
        cursor.execute("SELECT * FROM audit_logs WHERE document_id = ? ORDER BY id DESC LIMIT 100", (doc_id,))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()

    res = []
    for r in rows:
        res.append(AuditLogItem(
            id=r["id"],
            document_id=r["document_id"],
            timestamp=r["timestamp"],
            event_type=r["event_type"],
            actor=r["actor"],
            details=json.loads(r["details_json"]),
            tamper_hash=r["tamper_hash"]
        ))
    return res

# 13. Delete Document & Temporary Cleanup
@router.delete("/documents/{doc_id}")
def delete_document(doc_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM documents WHERE id = ?", (doc_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")

    fname = row["filename"]
    cursor.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    # Clean files
    try:
        raw_file = UPLOADS_DIR / fname
        if raw_file.exists():
            raw_file.unlink()
        for f in EXPORTS_DIR.glob(f"*{doc_id}*"):
            if f.exists():
                f.unlink()
    except Exception as e:
        print(f"File cleanup notice: {e}")

    log_audit_event(doc_id, "DOCUMENT_DELETED", "HUMAN_REVIEWER", {"document_id": doc_id})
    return {"message": "Document and associated files successfully deleted", "document_id": doc_id}

# 14. Settings & Policy Configuration
@router.get("/settings")
def get_settings():
    return {
        "role_default_actions": ROLE_DEFAULT_ACTIONS,
        "category_default_actions": CATEGORY_DEFAULT_ACTIONS,
        "pocso_strict_enforcement": True,
        "citation_preservation": True,
        "court_officer_review_flag": True,
        "mask_character": "*",
        "pseudonym_style": "ROLE_BASED",
        "legal_disclaimer": LEGAL_DISCLAIMER
    }
