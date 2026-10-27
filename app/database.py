import sqlite3
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.config import DB_PATH

def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        file_type TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        uploaded_at TEXT NOT NULL,
        status TEXT NOT NULL,
        text_content TEXT,
        page_count INTEGER DEFAULT 1,
        court_name TEXT,
        case_number TEXT,
        case_title TEXT,
        metadata_json TEXT
    );

    CREATE TABLE IF NOT EXISTS pii_entities (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL,
        text TEXT NOT NULL,
        category TEXT NOT NULL,
        start_char INTEGER NOT NULL,
        end_char INTEGER NOT NULL,
        page_number INTEGER DEFAULT 1,
        confidence REAL NOT NULL,
        predicted_role TEXT NOT NULL,
        role_confidence REAL NOT NULL,
        role_evidence TEXT,
        action TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        pseudonym TEXT,
        reviewer_notes TEXT,
        is_manual_addition INTEGER DEFAULT 0,
        FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS risk_assessments (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL,
        overall_score REAL NOT NULL,
        risk_level TEXT NOT NULL,
        breakdown_json TEXT NOT NULL,
        statutory_alerts_json TEXT NOT NULL,
        recommendations_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS redactions (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL,
        sanitized_text TEXT NOT NULL,
        export_pdf_path TEXT,
        export_docx_path TEXT,
        export_txt_path TEXT,
        mappings_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS residual_scans (
        id TEXT PRIMARY KEY,
        document_id TEXT NOT NULL,
        residual_score REAL NOT NULL,
        findings_json TEXT NOT NULL,
        scan_summary_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id TEXT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        details_json TEXT NOT NULL,
        tamper_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evaluation_benchmarks (
        id TEXT PRIMARY KEY,
        benchmark_name TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        regex_metrics_json TEXT NOT NULL,
        ner_metrics_json TEXT NOT NULL,
        nyayashield_metrics_json TEXT NOT NULL,
        dataset_summary_json TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

def log_audit_event(document_id: Optional[str], event_type: str, actor: str, details: Dict[str, Any]) -> str:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT tamper_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    prev_hash = row["tamper_hash"] if row else "GENESIS_NYAYASHIELD_ROOT"

    now_iso = datetime.utcnow().isoformat() + "Z"
    details_str = json.dumps(details, sort_keys=True)
    hash_payload = f"{prev_hash}|{now_iso}|{document_id or ''}|{event_type}|{actor}|{details_str}"
    current_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

    cursor.execute(
        """
        INSERT INTO audit_logs (document_id, timestamp, event_type, actor, details_json, tamper_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (document_id, now_iso, event_type, actor, details_str, current_hash)
    )
    conn.commit()
    conn.close()
    return current_hash
