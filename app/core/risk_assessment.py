from typing import List, Dict, Any
from app.config import LEGAL_DISCLAIMER

def calculate_privacy_risk(entities: List[Dict[str, Any]], full_text: str, is_post_redaction: bool = False) -> Dict[str, Any]:
    """Computes an explainable heuristic privacy risk score (0-100) and statutory risk alerts."""
    factors = []
    statutory_alerts = []
    recommendations = []

    # Category Sensitivities (Base impact weights)
    CATEGORY_WEIGHTS = {
        "AADHAAR": 30.0,
        "PAN": 25.0,
        "BANK_ACCOUNT": 25.0,
        "IFSC": 10.0,
        "UPI_ID": 20.0,
        "PHONE": 18.0,
        "EMAIL": 15.0,
        "RESIDENTIAL_ADDRESS": 22.0,
        "VEHICLE_NUMBER": 16.0,
        "DATE_OF_BIRTH": 14.0,
        "AGE": 8.0,
        "PERSON_NAME": 15.0,
        "PASSPORT": 28.0,
        "VOTER_ID": 22.0,
    }

    # Role Multipliers
    ROLE_MULTIPLIERS = {
        "VICTIM": 2.2,
        "MINOR": 2.2,
        "FAMILY_MEMBER": 1.7,
        "WITNESS": 1.5,
        "PETITIONER": 1.3,
        "RESPONDENT": 1.3,
        "ACCUSED": 1.2,
        "GENERAL_INDIVIDUAL": 1.0,
        "LAWYER": 0.3,
        "JUDGE": 0.2,
        "POLICE_OFFICER": 0.4,
    }

    total_weighted_exposure = 0.0
    category_counts: Dict[str, int] = {}
    role_counts: Dict[str, int] = {}
    uncertain_entities = 0

    for ent in entities:
        cat = ent.get("category", "PERSON_NAME")
        role = ent.get("predicted_role", "GENERAL_INDIVIDUAL")
        conf = ent.get("confidence", 0.8)
        action = ent.get("action", "REDACT")
        status = ent.get("status", "PENDING")

        category_counts[cat] = category_counts.get(cat, 0) + 1
        role_counts[role] = role_counts.get(role, 0) + 1

        if conf < 0.75:
            uncertain_entities += 1

        # Calculate entity impact
        base_weight = CATEGORY_WEIGHTS.get(cat, 12.0)
        role_mult = ROLE_MULTIPLIERS.get(role, 1.0)
        
        # If redacted or masked, risk impact is substantially mitigated
        mitigation = 1.0
        if is_post_redaction:
            if status in ("APPROVED", "MODIFIED") and action in ("REDACT", "MASK", "PSEUDONYMIZE"):
                mitigation = 0.05  # 95% reduction
            elif action == "REVIEW":
                mitigation = 0.60  # Still uncertain

        impact = base_weight * role_mult * mitigation * conf
        total_weighted_exposure += impact

    # Normalize to 0-100 scale using non-linear saturation
    # ~150 weighted points corresponds to high risk (80+)
    score = min(100.0, round((total_weighted_exposure / (total_weighted_exposure + 80.0)) * 100.0, 1)) if total_weighted_exposure > 0 else 0.0

    # 1. Contributing Factors
    if "AADHAAR" in category_counts or "PAN" in category_counts:
        factors.append({
            "factor": "Statutory National Identifiers Exposed",
            "category": "DIRECT_IDENTIFIER",
            "weight": 28.0,
            "impact_score": min(30.0, (category_counts.get("AADHAAR", 0) + category_counts.get("PAN", 0)) * 14.0),
            "description": f"Found {category_counts.get('AADHAAR', 0)} Aadhaar number(s) and {category_counts.get('PAN', 0)} PAN card(s). High danger of financial identity theft."
        })

    if "VICTIM" in role_counts or "MINOR" in role_counts:
        victim_minor_count = role_counts.get("VICTIM", 0) + role_counts.get("MINOR", 0)
        factors.append({
            "factor": "Vulnerable Legal Roles (Victim / Minor / Child)",
            "category": "STATUTORY_PROTECTION",
            "weight": 35.0,
            "impact_score": min(40.0, victim_minor_count * 20.0),
            "description": f"Detected {victim_minor_count} references to Victims or Minor children. Strict statutory non-disclosure penalties apply under Indian law."
        })

    if "RESIDENTIAL_ADDRESS" in category_counts:
        factors.append({
            "factor": "Geographic Localization Risk",
            "category": "QUASI_IDENTIFIER",
            "weight": 22.0,
            "impact_score": min(25.0, category_counts["RESIDENTIAL_ADDRESS"] * 10.0),
            "description": f"Identified {category_counts['RESIDENTIAL_ADDRESS']} residential address strings. Re-identification risk increases drastically when combined with names or parentage."
        })

    if "FAMILY_MEMBER" in role_counts:
        factors.append({
            "factor": "Parentage Linkage Leakage",
            "category": "RELATIONAL_LEAKAGE",
            "weight": 18.0,
            "impact_score": min(20.0, role_counts["FAMILY_MEMBER"] * 9.0),
            "description": f"Detected {role_counts['FAMILY_MEMBER']} parentage references ('S/o', 'D/o', 'W/o'). In Indian jurisprudence, parentage often leads to indirect victim or party re-identification."
        })

    if uncertain_entities > 0:
        factors.append({
            "factor": "Low-Confidence Classification Uncertainty",
            "category": "UNCERTAINTY",
            "weight": 12.0,
            "impact_score": min(15.0, uncertain_entities * 4.0),
            "description": f"{uncertain_entities} entities detected with confidence < 75%. Require human verification to avoid accidental exposure or over-redaction."
        })

    # 2. Statutory Alerts (Indian Legal Framework)
    text_lower = full_text.lower()
    has_pocso = "pocso" in text_lower or "protection of children from sexual offences" in text_lower
    has_rape_ipc = "376" in text_lower or "rape" in text_lower or "prosecutrix" in text_lower
    has_juvenile = "juvenile" in text_lower or "jj act" in text_lower or "child in conflict" in text_lower

    if has_pocso or role_counts.get("MINOR", 0) > 0:
        statutory_alerts.append({
            "statute": "POCSO Act, 2012",
            "section": "Sections 24, 33(7) & 37",
            "severity": "CRITICAL",
            "rationale": "Mandatory statutory prohibition against disclosing the identity of any child victim or child involved in proceedings.",
            "guidance": "All names, schools, parentage, locality, and family references of the minor MUST be pseudonymized or redacted."
        })

    if has_rape_ipc or role_counts.get("VICTIM", 0) > 0:
        statutory_alerts.append({
            "statute": "Indian Penal Code / Bharatiya Nyaya Sanhita",
            "section": "Section 228A IPC (Section 72 BNS) & Section 327 CrPC",
            "severity": "CRITICAL",
            "rationale": "Disclosure of identity of victim of sexual offences is a cognizable criminal offense punishable with up to 2 years imprisonment.",
            "guidance": "Supreme Court in 'Nipun Saxena v. UOI' mandates that judgment copies must strictly conceal the prosecutrix's identity and any indirect linkage facts."
        })

    if has_juvenile:
        statutory_alerts.append({
            "statute": "Juvenile Justice (Care and Protection of Children) Act, 2015",
            "section": "Section 74",
            "severity": "HIGH",
            "rationale": "Prohibition on disclosure of identity of children alleged to be in conflict with law or children in need of care.",
            "guidance": "Use initials or generic pseudonyms such as [CHILD_1] or [JUVENILE_A]."
        })

    # Digital Personal Data Protection Act, 2023
    statutory_alerts.append({
        "statute": "Digital Personal Data Protection Act, 2023 (DPDPA)",
        "section": "Section 4 & 8",
        "severity": "MEDIUM",
        "rationale": "Data fiduciary obligation to safeguard digital personal data and ensure data minimization during electronic publication of public court records.",
        "guidance": "Mask financial accounts, Aadhaar, PAN, phone numbers, and private residential coordinates before digital indexing."
    })

    # 3. Recommendations
    if role_counts.get("VICTIM", 0) > 0 or role_counts.get("MINOR", 0) > 0:
        recommendations.append("Apply PSEUDONYMIZE to all Victim and Minor entities immediately before document export.")
    if "AADHAAR" in category_counts or "PAN" in category_counts or "BANK_ACCOUNT" in category_counts:
        recommendations.append("Enforce solid REDACT on all national IDs and bank account numbers.")
    if "FAMILY_MEMBER" in role_counts:
        recommendations.append("Review parentage statements ('S/o', 'W/o') to prevent indirect jigsaw identification.")
    if uncertain_entities > 0:
        recommendations.append(f"Complete manual review on the {uncertain_entities} flagged low-confidence entities in the Review Workbench.")
    recommendations.append("Execute the Residual PII Leakage Scan pass after applying redactions.")

    # Risk level threshold
    if score >= 80.0:
        risk_level = "CRITICAL"
    elif score >= 55.0:
        risk_level = "HIGH"
    elif score >= 30.0:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    return {
        "overall_score": score,
        "risk_level": risk_level,
        "factors": factors,
        "statutory_alerts": statutory_alerts,
        "recommendations": recommendations,
        "disclaimer": LEGAL_DISCLAIMER,
    }
