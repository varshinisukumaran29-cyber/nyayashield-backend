import os
import secrets
import uuid
import json
import shutil
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Depends, Security
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
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

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: Optional[str] = Security(api_key_header)):
    expected_key = os.environ.get("NYAYASHIELD_API_KEY")
    if not expected_key:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    if not api_key or not secrets.compare_digest(api_key, expected_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


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
@router.post("/documents/upload", response_model=Dict[str, Any], dependencies=[Depends(verify_api_key)])
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