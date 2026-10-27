import pytest
from app.core.legal_role_engine import analyze_legal_role

def test_judge_and_lawyer_role_classification():
    text = (
        "CORAM: HON'BLE MR. JUSTICE SURESH KUMAR KAIT. "
        "Appearances: Mr. Kapil Sibal, Senior Advocate for the Petitioner."
    )
    judge_role = analyze_legal_role("SURESH KUMAR KAIT", "PERSON_NAME", text, 27, 44)
    assert judge_role["predicted_role"] == "JUDGE"
    assert judge_role["role_confidence"] >= 0.90

    lawyer_role = analyze_legal_role("Kapil Sibal", "PERSON_NAME", text, 66, 77)
    assert lawyer_role["predicted_role"] == "LAWYER"

def test_victim_and_minor_role_classification():
    text = (
        "Under Section 6 of the POCSO Act, the prosecution examined victim Priya Sharma, "
        "aged 13 years, who was lured into the premises."
    )
    victim_role = analyze_legal_role("Priya Sharma", "PERSON_NAME", text, 66, 78)
    assert victim_role["predicted_role"] in ("VICTIM", "MINOR")
    assert "POCSO" in victim_role["role_evidence"] or "victim" in victim_role["role_evidence"].lower()

def test_parentage_family_member_classification():
    text = "The applicant Ramesh Kumar, S/o Shri Harish Kumar, approached this court."
    harish_role = analyze_legal_role("Harish Kumar", "PERSON_NAME", text, 38, 50)
    assert harish_role["predicted_role"] == "FAMILY_MEMBER"
    assert "family_member" in harish_role["role_evidence"].lower() or "parentage" in harish_role["role_evidence"].lower()
