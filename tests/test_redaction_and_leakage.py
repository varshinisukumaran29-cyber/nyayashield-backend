import pytest
from app.core.redaction_engine import generate_pseudonym_mapping, redact_text_content, apply_mask
from app.core.residual_scanner import scan_residual_leakage

def test_consistent_pseudonymization():
    entities = [
        {"text": "Priya Sharma", "category": "PERSON_NAME", "predicted_role": "VICTIM"},
        {"text": "priya sharma", "category": "PERSON_NAME", "predicted_role": "VICTIM"},
        {"text": "Ramesh Kumar", "category": "PERSON_NAME", "predicted_role": "ACCUSED"},
    ]
    mapping = generate_pseudonym_mapping(entities, style="ROLE_BASED")

    # Consistent mapping: same case-insensitive identity maps to exact same pseudonym
    assert mapping["priya sharma"] == "[VICTIM_1]"
    assert mapping["ramesh kumar"] == "[ACCUSED_1]"

def test_masking_format_preservation():
    aadhaar_masked = apply_mask("2341 5678 9012", "AADHAAR")
    assert aadhaar_masked.startswith("XXXX-XXXX-")
    assert aadhaar_masked.endswith("9012")

    pan_masked = apply_mask("ABCDE1234F", "PAN")
    assert pan_masked.startswith("AB")
    assert pan_masked.endswith("4F")

def test_residual_leakage_detection():
    sanitized_clean = (
        "In the matter of [APPELLANT_1] versus State. "
        "The complainant [VICTIM_1] deposed that the incident occurred."
    )
    entities = [
        {"text": "Ramesh Kumar", "category": "PERSON_NAME", "action": "PSEUDONYMIZE", "status": "APPROVED"},
        {"text": "Priya Sharma", "category": "PERSON_NAME", "action": "PSEUDONYMIZE", "status": "APPROVED"},
    ]
    clean_res = scan_residual_leakage(sanitized_clean, entities)
    assert clean_res["residual_score"] == 0.0
    assert len(clean_res["findings"]) == 0

    # Test leaked text: an unredacted Aadhaar and surviving name
    sanitized_leaked = (
        "In the matter of Ramesh Kumar versus State. "
        "Aadhaar: 2341 5678 9012 was produced."
    )
    leaked_res = scan_residual_leakage(sanitized_leaked, entities)
    assert leaked_res["residual_score"] > 0
    assert len(leaked_res["findings"]) >= 1
