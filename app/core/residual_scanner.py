import re
from typing import List, Dict, Any
from app.core.pii_engine import detect_pii_entities

RESIDUAL_DISCLAIMER = (
    "NyayaShield AI Residual Scanner performs an automated second-pass heuristic inspection. "
    "Even if zero residual indicators are detected, automated scans cannot guarantee absolute anonymity. "
    "Contextual jigsaw inferences or domain-specific nuances require independent human legal review."
)

def scan_residual_leakage(sanitized_text: str, original_entities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Independent second-pass scan to verify whether any sensitive information or partial tokens leaked."""
    findings = []
    
    # 1. Independent Second-Pass Scan on Sanitized Output
    second_pass_matches = detect_pii_entities(sanitized_text)

    # Filter out false alarms where the match is inside our redaction tags like [AADHAAR_REDACTED] or [VICTIM_1]
    tag_pattern = re.compile(r'\[[A-Z0-9_]+\]')
    tag_spans = [(m.start(), m.end()) for m in tag_pattern.finditer(sanitized_text)]

    def is_inside_tag(start: int, end: int) -> bool:
        for ts, te in tag_spans:
            if not (end <= ts or start >= te):
                return True
        return False

    for match in second_pass_matches:
        if is_inside_tag(match["start_char"], match["end_char"]):
            continue

        # Extract surrounding context
        ctx_start = max(0, match["start_char"] - 35)
        ctx_end = min(len(sanitized_text), match["end_char"] + 35)
        snippet = sanitized_text[ctx_start:ctx_end].replace("\n", " ").strip()

        findings.append({
            "token": match["text"],
            "suspected_category": match["category"],
            "context_snippet": f"...{snippet}...",
            "char_offset": match["start_char"],
            "confidence": match["confidence"],
            "flag_reason": f"Secondary independent scan detected unredacted {match['category']}: {match.get('explanation', '')}",
        })

    # 2. Cross-check: Did any original entity text verbatim survive in sanitized_text without masking?
    for orig in original_entities:
        orig_text = orig.get("text", "").strip()
        orig_action = orig.get("action", "REDACT")
        orig_status = orig.get("status", "PENDING")

        # Skip if action was REVIEW or status was REJECTED by human
        if orig_action == "REVIEW" or orig_status == "REJECTED":
            continue

        if len(orig_text) > 3 and orig_text.lower() in sanitized_text.lower():
            # Check if this occurrence is already reported in findings
            already_reported = any(f["token"].lower() == orig_text.lower() for f in findings)
            if not already_reported:
                pos = sanitized_text.lower().find(orig_text.lower())
                ctx_start = max(0, pos - 30)
                ctx_end = min(len(sanitized_text), pos + len(orig_text) + 30)
                snippet = sanitized_text[ctx_start:ctx_end].replace("\n", " ").strip()
                findings.append({
                    "token": orig_text,
                    "suspected_category": orig.get("category", "PERSON_NAME"),
                    "context_snippet": f"...{snippet}...",
                    "char_offset": pos,
                    "confidence": 0.95,
                    "flag_reason": "Original entity text survived verbatim in sanitized output despite approved redaction directive.",
                })

    # 3. Check for Parentage Orphan Leaks (e.g. "S/o [REDACTED]" or "[PETITIONER_1] son of Ram Lal")
    parentage_leak_regex = re.compile(r'\b(?:s/o|d/o|w/o|son of|daughter of|wife of)\s+([A-Za-z]{3,25})\b', re.IGNORECASE)
    for m in parentage_leak_regex.finditer(sanitized_text):
        token = m.group(1)
        if token.upper() not in ["REDACTED", "ANON", "PSEUDONYM", "CONFIDENTIAL"]:
            ctx_start = max(0, m.start() - 30)
            ctx_end = min(len(sanitized_text), m.end() + 30)
            snippet = sanitized_text[ctx_start:ctx_end].replace("\n", " ").strip()
            findings.append({
                "token": token,
                "suspected_category": "FAMILY_MEMBER",
                "context_snippet": f"...{snippet}...",
                "char_offset": m.start(),
                "confidence": 0.88,
                "flag_reason": f"Potential parentage linkage leak following '{m.group(0).split()[0]}'",
            })

    # Compute Residual Score (0.0 means completely clean)
    leakage_count = len(findings)
    total_original = max(1, len(original_entities))
    
    # Scale: each leaked finding adds residual risk
    residual_score = min(100.0, round(leakage_count * 15.0, 1))
    cleanliness_rate = max(0.0, round(100.0 - residual_score, 1))

    summary = {
        "total_scanned_chars": len(sanitized_text),
        "total_original_entities": total_original,
        "leakage_findings_count": leakage_count,
        "cleanliness_percentage": cleanliness_rate,
        "status": "PASS" if leakage_count == 0 else "FAIL_LEAKAGE_DETECTED",
    }

    return {
        "residual_score": residual_score,
        "cleanliness_rate": cleanliness_rate,
        "findings": findings,
        "summary": summary,
        "uncertain_flag_count": leakage_count,
        "disclaimer": RESIDUAL_DISCLAIMER,
    }
