import re
from typing import Dict, Any, List

ROLE_PATTERNS = {
    "JUDGE": [
        (re.compile(r'(?:Hon\'ble|Honourable)\s+(?:Mr\.|Ms\.|Mrs\.)?\s*Justice\s+([A-Za-z\s]+)', re.IGNORECASE), 0.95),
        (re.compile(r'CORAM\s*:\s*(?:HON\'BLE\s+)?(?:MR\.|MS\.)?\s*JUSTICE\s+([A-Za-z\s,]+)', re.IGNORECASE), 0.96),
        (re.compile(r'BEFORE\s*:\s*(?:HON\'BLE\s+)?(?:MR\.|MS\.)?\s*JUSTICE\s+([A-Za-z\s,]+)', re.IGNORECASE), 0.95),
        (re.compile(r'([A-Za-z\s]+),\s*(?:C\.?J\.?|J\.)\b', re.IGNORECASE), 0.92),
    ],
    "LAWYER": [
        (re.compile(r'(?:Advocate|Adv\.|Senior\s+Advocate|Counsel|Sr\.\s+Adv\.)\s+(?:for\s+(?:the\s+)?[A-Za-z\s]+)?[:\s]+([A-Za-z\s.,]+)', re.IGNORECASE), 0.92),
        (re.compile(r'(?:Learned\s+)?(?:APP|Addl\.\s+PP|Public\s+Prosecutor|Standing\s+Counsel)\s+(?:Mr\.|Ms\.)?\s*([A-Za-z\s]+)', re.IGNORECASE), 0.94),
        (re.compile(r'Appearance[s]?\s*:\s*(?:For\s+[A-Za-z]+)?[:\s]+([A-Za-z\s.,]+)', re.IGNORECASE), 0.88),
    ],
    "VICTIM": [
        (re.compile(r'\b(?:victim|prosecutrix|deceased|injured|casualty)\s+(?:namely\s+)?([A-Za-z\s]+)', re.IGNORECASE), 0.96),
        (re.compile(r'\b([A-Za-z\s]+)\s*\((?:victim|prosecutrix)\)', re.IGNORECASE), 0.95),
    ],
    "MINOR": [
        (re.compile(r'\b(?:minor(?:\s+child)?|juvenile|child|daughter|son)\s+(?:aged\s+(?:about\s+)?(?:[0-9]|1[0-7])\s+years?|namely)\s+([A-Za-z\s]+)', re.IGNORECASE), 0.95),
        (re.compile(r'\bMaster\s+([A-Za-z\s]+)\s*,\s*aged\s*(?:about\s*)?(?:[0-9]|1[0-7])', re.IGNORECASE), 0.94),
        (re.compile(r'\bBaby\s+([A-Za-z\s]+)\s*,\s*aged\s*(?:about\s*)?(?:[0-9]|1[0-7])', re.IGNORECASE), 0.94),
    ],
    "WITNESS": [
        (re.compile(r'\b(?:PW|DW|CW)[ -]?\d+[:\s-]+([A-Za-z\s]+)', re.IGNORECASE), 0.94),
        (re.compile(r'\b(?:prosecution|defense|eye|material|panch)\s+witness\s+(?:namely\s+)?([A-Za-z\s]+)', re.IGNORECASE), 0.92),
    ],
    "POLICE_OFFICER": [
        (re.compile(r'\b(?:I\.?O\.?|Investigating\s+Officer|Inspector|Sub-Inspector|SI|SHO|Constable)\s+([A-Za-z\s]+)', re.IGNORECASE), 0.93),
    ],
    "FAMILY_MEMBER": [
        (re.compile(r'\b(?:S/o|D/o|W/o|Son\s+of|Daughter\s+of|Wife\s+of|husband\s+of|father\s+of|mother\s+of)\s+([A-Za-z\s]+)', re.IGNORECASE), 0.91),
    ],
    "PETITIONER": [
        (re.compile(r'([A-Za-z\s]+)\s*\.{2,}\s*(?:Petitioner|Appellant|Applicant|Complainant)\b', re.IGNORECASE), 0.93),
        (re.compile(r'\b(?:Petitioner|Appellant|Applicant|Complainant)\s*[:\s]+([A-Za-z\s]+)', re.IGNORECASE), 0.90),
    ],
    "RESPONDENT": [
        (re.compile(r'([A-Za-z\s]+)\s*\.{2,}\s*(?:Respondent|Non-Applicant)\b', re.IGNORECASE), 0.93),
        (re.compile(r'\b(?:Respondent|Non-Applicant)\s*[:\s]+([A-Za-z\s]+)', re.IGNORECASE), 0.90),
    ],
    "ACCUSED": [
        (re.compile(r'\b(?:accused|convict|undertrial|culprit)\s+(?:No\.?\s*\d+\s+)?(?:namely\s+)?([A-Za-z\s]+)', re.IGNORECASE), 0.92),
    ],
}

def analyze_legal_role(entity_text: str, category: str, full_text: str, start_char: int, end_char: int) -> Dict[str, Any]:
    """Analyzes document structural context to classify the legal role of an entity with evidence."""
    # If not a person or address, role is tied to identifier
    if category in ("AADHAAR", "PAN", "BANK_ACCOUNT", "IFSC", "UPI_ID", "PHONE", "EMAIL", "VEHICLE_NUMBER"):
        return {
            "predicted_role": "GENERAL_INDIVIDUAL",
            "role_confidence": 0.85,
            "role_evidence": f"Individual identifier category: {category}",
        }

    # Extract surrounding window (-180 to +180 characters)
    window_start = max(0, start_char - 180)
    window_end = min(len(full_text), end_char + 180)
    context_window = full_text[window_start:window_end]

    # Check structural title block (first 1000 characters often define Petitioner vs Respondent)
    is_in_header = start_char < 1200
    cleaned_name = re.escape(entity_text.strip())

    # 1. Check direct role patterns in the context window
    for role, pattern_list in ROLE_PATTERNS.items():
        for pattern, base_conf in pattern_list:
            match = pattern.search(context_window)
            if match:
                matched_text = match.group(0)
                if entity_text.lower() in matched_text.lower():
                    evidence = f"Matched contextual keyword '{role}' in excerpt: '...{matched_text.strip()}...'"
                    return {
                        "predicted_role": role,
                        "role_confidence": base_conf,
                        "role_evidence": evidence
                    }

    # 2. Check POCSO / Sexual Offense / Minor context
    sexual_offense_terms = ["pocso", "376", "rape", "sexual assault", "molestation", "aggravated"]
    doc_lower = full_text[:4000].lower()
    is_sexual_offense_case = any(term in doc_lower for term in sexual_offense_terms)

    # If the case mentions POCSO / 376 IPC and the entity is near 'prosecutrix' or 'child' or 'victim'
    if is_sexual_offense_case:
        win_lower = context_window.lower()
        if any(w in win_lower for w in ["victim", "prosecutrix", "girl", "daughter", "child"]):
            return {
                "predicted_role": "VICTIM",
                "role_confidence": 0.94,
                "role_evidence": "Classified as Victim under statutory POCSO / Section 228A IPC context (proximity to victim/prosecutrix references)",
            }
        if any(w in win_lower for w in ["minor", "aged", "school", "student", "class"]):
            return {
                "predicted_role": "MINOR",
                "role_confidence": 0.92,
                "role_evidence": "Classified as Minor/Child under Juvenile protection context",
            }

    # 3. Check Parentage (S/o, D/o, W/o)
    parentage_match = re.search(r'\b(?:s/o|d/o|w/o|son of|daughter of|wife of)\s+' + cleaned_name, context_window, re.IGNORECASE)
    if parentage_match:
        return {
            "predicted_role": "FAMILY_MEMBER",
            "role_confidence": 0.91,
            "role_evidence": f"Identified as family member via parentage syntax: '{parentage_match.group(0)}'",
        }

    # 4. Check Title Block / Versus
    if is_in_header:
        header_text = full_text[:1500]
        versus_match = re.search(r'(.+?)(?:\s+versus\s+|\s+vs\.?\s+|\s+v\.\s+)(.+)', header_text, re.IGNORECASE | re.DOTALL)
        if versus_match:
            petitioner_side = versus_match.group(1)
            respondent_side = versus_match.group(2)
            if entity_text.lower() in petitioner_side.lower():
                return {
                    "predicted_role": "PETITIONER",
                    "role_confidence": 0.88,
                    "role_evidence": "Found on Petitioner / Appellant side of title block",
                }
            elif entity_text.lower() in respondent_side.lower():
                return {
                    "predicted_role": "RESPONDENT",
                    "role_confidence": 0.88,
                    "role_evidence": "Found on Respondent / Accused side of title block",
                }

    # Default fallback
    return {
        "predicted_role": "GENERAL_INDIVIDUAL",
        "role_confidence": 0.70,
        "role_evidence": "Default private individual role inferred from linguistic NER recognition without specific court officer or victim markers",
    }
