import pytest
from app.core.pii_engine import detect_pii_entities, validate_verhoeff, generate_verhoeff, get_exclusion_spans

def test_verhoeff_aadhaar_validation():
    # Dynamically generate a mathematically valid 12-digit Aadhaar with correct Verhoeff checksum
    valid_aadhaar = generate_verhoeff("23415678901")
    assert len(valid_aadhaar) == 12
    assert validate_verhoeff(valid_aadhaar) is True

    # Invalid Aadhaar with corrupted check digit
    corrupted = valid_aadhaar[:-1] + str((int(valid_aadhaar[-1]) + 1) % 10)
    assert validate_verhoeff(corrupted) is False

def test_legal_citations_and_acts_exclusion():
    text = (
        "In AIR 2021 SC 554 and (2018) 4 SCC 120, the Supreme Court of India "
        "interpreted Section 302 of the Indian Penal Code and Section 438 Cr.P.C. "
        "in Criminal Appeal No. 124 of 2020."
    )
    exclusions = get_exclusion_spans(text)
    assert len(exclusions) >= 3

    # Ensure none of these legal terms are falsely detected as PII
    entities = detect_pii_entities(text)
    names = [e["text"] for e in entities if e["category"] == "PERSON_NAME"]
    for citation in ["AIR 2021 SC 554", "4 SCC 120", "Section 302", "Criminal Appeal"]:
        assert citation not in names

def test_indian_identifiers_detection():
    text = (
        "The accused furnished PAN Card ABCDE1234F, Aadhaar 2341 5678 9012, "
        "IFSC SBIN0001234, and contact mobile 9811234567, email contact@nyayashield.org."
    )
    entities = detect_pii_entities(text)
    categories = {e["category"] for e in entities}

    assert "PAN" in categories
    assert "AADHAAR" in categories
    assert "IFSC" in categories
    assert "PHONE" in categories
    assert "EMAIL" in categories

def test_contextual_residential_address_detection():
    text = (
        "Petitioner resides at House No. 45-B, Gali No. 3, Begumpur, New Delhi - 110017 "
        "and is currently staying in village Kasan, Tehsil Manesar, District Gurugram, Haryana."
    )
    entities = detect_pii_entities(text)
    addresses = [e for e in entities if e["category"] == "RESIDENTIAL_ADDRESS"]
    assert len(addresses) >= 1
