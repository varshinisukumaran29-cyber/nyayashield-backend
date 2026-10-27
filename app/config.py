import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = BASE_DIR / "uploads"
EXPORTS_DIR = BASE_DIR / "exports"
DB_PATH = DATA_DIR / "nyayashield.db"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Security and Limits
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt"}

# Redaction Configuration
ROLE_DEFAULT_ACTIONS = {
    "VICTIM": "PSEUDONYMIZE",
    "MINOR": "PSEUDONYMIZE",
    "WITNESS": "PSEUDONYMIZE",
    "PETITIONER": "PSEUDONYMIZE",
    "RESPONDENT": "PSEUDONYMIZE",
    "ACCUSED": "PSEUDONYMIZE",
    "FAMILY_MEMBER": "PSEUDONYMIZE",
    "JUDGE": "REVIEW",
    "LAWYER": "REVIEW",
    "POLICE_OFFICER": "REVIEW",
    "GENERAL_INDIVIDUAL": "PSEUDONYMIZE",
}

CATEGORY_DEFAULT_ACTIONS = {
    "AADHAAR": "REDACT",
    "PAN": "REDACT",
    "BANK_ACCOUNT": "REDACT",
    "IFSC": "MASK",
    "UPI_ID": "REDACT",
    "PHONE": "MASK",
    "EMAIL": "MASK",
    "VEHICLE_NUMBER": "MASK",
    "RESIDENTIAL_ADDRESS": "PSEUDONYMIZE",
    "DATE_OF_BIRTH": "MASK",
    "AGE": "MASK",
    "PERSON_NAME": "PSEUDONYMIZE",
}

# Legal Disclaimers
LEGAL_DISCLAIMER = (
    "NyayaShield AI provides heuristic privacy risk assessments, context-aware PII detection, "
    "and automated redaction recommendations to assist legal professionals. "
    "It does not constitute certified legal compliance advice. Final verification by a qualified "
    "human legal reviewer is strictly recommended before public disclosure."
)
