import re
from typing import List, Dict, Any, Tuple
# Try loading spaCy pipeline with fallback to pure-python legal NLP if blocked by WDAC
try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except Exception as e:
    SPACY_AVAILABLE = False
    nlp = None

# Verhoeff Algorithm for Aadhaar Validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 6, 7, 8, 9, 0, 1, 2, 3, 4],
    [6, 7, 8, 9, 5, 1, 2, 3, 4, 0],
    [7, 8, 9, 5, 6, 2, 3, 4, 0, 1],
    [8, 9, 5, 6, 7, 3, 4, 0, 1, 2],
    [9, 5, 6, 7, 8, 4, 0, 1, 2, 3],
]
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def generate_verhoeff(num_str: str) -> str:
    """Generates a valid 12-digit Aadhaar number with the correct Verhoeff check digit."""
    digits = [int(c) for c in num_str if c.isdigit()]
    c = 0
    reversed_digits = digits[::-1]
    for i, item in enumerate(reversed_digits):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][item]]
    return "".join(map(str, digits)) + str(VERHOEFF_INV[c])

def validate_verhoeff(num_str: str) -> bool:
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    reversed_digits = digits[::-1]
    for i, item in enumerate(reversed_digits):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][item]]
    return c == 0

# Legal Exclusions (Case numbers, citations, Acts, court names)
CITATION_PATTERNS = [
    re.compile(r'\bAIR\s+\d{4}\s+(?:SC|Del|Bom|Mad|Cal|All|Kar)\s+\d+\b', re.IGNORECASE),
    re.compile(r'\(\d{4}\)\s+\d+\s+SCC\s+\d+\b', re.IGNORECASE),
    re.compile(r'\b\d{4}\s+LiveLaw\s+\([A-Z]+\)\s+\d+\b', re.IGNORECASE),
    re.compile(r'\bILR\s+\d{4}\s+[A-Za-z]+\s+\d+\b', re.IGNORECASE),
    re.compile(r'\b\d{4}\s+Cri(?:minal)?\s+L\.?J\.?\s+\d+\b', re.IGNORECASE),
    re.compile(r'\b\d{4}\s+SCC\s+OnLine\s+[A-Za-z]+\s+\d+\b', re.IGNORECASE),
    re.compile(r'\b(?:19|20)\d{2}\s+SCR\s+\d+\b', re.IGNORECASE),
]

CASE_NUMBER_PATTERNS = [
    re.compile(r'\b(?:Crl\.?A\.?|Criminal\s+Appeal|W\.?P\.?|Writ\s+Petition|SLP|S\.L\.P\.|Bail\s+Appln\.?|C\.?S\.?|O\.?M\.?P\.?|Company\s+Petition|Mat\.?App\.?)\s*(?:\([A-Za-z]+\))?\s*(?:No\.?|Number)?\s*\d+[\s/of]+\d{2,4}\b', re.IGNORECASE),
    re.compile(r'\bFIR\s+No\.?\s*\d+[\s/of]+\d{2,4}\b', re.IGNORECASE),
    re.compile(r'\bP\.?S\.?\s+[A-Za-z\s]+(?:\s+FIR\s+No\.?\s*\d+)?\b', re.IGNORECASE),
]

ACT_SECTION_PATTERNS = [
    re.compile(r'\bSection\s+\d+[A-Z]?(?:\s*\(\d+\))*(?:\s*\([a-z]\))*(?:\s+(?:of|read\s+with)\s+(?:the\s+)?(?:IPC|Indian\s+Penal\s+Code|Cr\.?P\.?C\.?|Code\s+of\s+Criminal\s+Procedure|POCSO(?:\s+Act)?|Negotiable\s+Instruments\s+Act|NI\s+Act|Hindu\s+Marriage\s+Act|Motor\s+Vehicles\s+Act|Evidence\s+Act|Constitution\s+of\s+India|CPC))?\b', re.IGNORECASE),
    re.compile(r'\bArticle\s+\d+[A-Z]?(?:\s*\(\d+\))*(?:\s+of\s+the\s+Constitution(?:\s+of\s+India)?)?\b', re.IGNORECASE),
    re.compile(r'\bSec\.?\s*\d+[A-Z]?\b', re.IGNORECASE),
]

COURT_PATTERNS = [
    re.compile(r'\b(?:Supreme\s+Court\s+of\s+India|High\s+Court\s+of\s+Judicature\s+at\s+[A-Za-z]+|High\s+Court\s+of\s+[A-Za-z]+|District\s+(?:and|&)\s+Sessions\s+Court|Family\s+Court|Sessions\s+Judge|Metropolitan\s+Magistrate)\b', re.IGNORECASE),
]

# Regex Recognizers for Indian PII
AADHAAR_REGEX = re.compile(r'\b[2-9]{1}[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b')
PAN_REGEX = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')
INDIAN_PHONE_REGEX = re.compile(r'\b(?:(?:\+91|91|0)?[ -]?)?[6-9]\d{9}\b')
LANDLINE_REGEX = re.compile(r'\b0\d{2,4}[-\s]?\d{6,8}\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
IFSC_REGEX = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
UPI_REGEX = re.compile(r'\b[a-zA-Z0-9._-]{2,64}@[a-zA-Z]{2,32}\b')
VEHICLE_REGEX = re.compile(r'\b[A-Z]{2}[-\s]?[0-9]{1,2}[-\s]?[A-Z]{1,3}[-\s]?[0-9]{4}\b')
PASSPORT_REGEX = re.compile(r'\b[A-Z][1-9][0-9]{7}\b')
VOTER_ID_REGEX = re.compile(r'\b[A-Z]{3}[0-9]{7}\b')
PIN_CODE_REGEX = re.compile(r'\b(?:Pin(?:\s*code)?|Postal\s+Code)?[ -]?([1-9][0-9]{5})\b', re.IGNORECASE)

DOB_AGE_REGEX = re.compile(r'\b(?:(?:born\s+on|DOB|D\.O\.B\.?:?)\s*(\d{1,2}[-/.](?:\d{1,2}|[A-Za-z]{3,9})[-/.]\d{2,4})|(?:aged?\s+(?:about\s+)?(\d{1,2})\s*years?))\b', re.IGNORECASE)

# Bank Account (Contextual: requires bank/account keywords nearby)
BANK_ACCOUNT_KEYWORDS = ["account", "a/c", "acct", "bank", "savings", "current account", "sbi", "hdfc", "icici", "pnb", "axis"]

# Indian Address Contextual Recognizer
ADDRESS_KEYWORDS = [
    r'r/o\b', r'resident\s+of\b', r'village\b', r'gram\b', r'taluk\b', r'tehsil\b',
    r'distt\.?\b', r'district\b', r'mohalla\b', r'gali\b', r'colony\b', r'nagar\b',
    r'sector\b', r'marg\b', r'road\b', r'house\s+no\.?\b', r'flat\s+no\.?\b', r'h\.no\.?\b',
    r'po\b', r'p\.o\.\b', r'police\s+station\b', r'p\.s\.\b'
]
ADDRESS_TRIGGER_REGEX = re.compile(r'(?:' + '|'.join(ADDRESS_KEYWORDS) + r')', re.IGNORECASE)

class PIIEntityMatch:
    def __init__(self, text: str, category: str, start: int, end: int, confidence: float, explanation: str):
        self.text = text
        self.category = category
        self.start = start
        self.end = end
        self.confidence = confidence
        self.explanation = explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "category": self.category,
            "start_char": self.start,
            "end_char": self.end,
            "confidence": round(self.confidence, 3),
            "explanation": self.explanation,
        }

def get_exclusion_spans(text: str) -> List[Tuple[int, int]]:
    """Identifies text spans for legal citations, case numbers, and Acts to avoid false positives."""
    exclusion_spans = []
    all_patterns = CITATION_PATTERNS + CASE_NUMBER_PATTERNS + ACT_SECTION_PATTERNS + COURT_PATTERNS
    for pattern in all_patterns:
        for m in pattern.finditer(text):
            exclusion_spans.append((m.start(), m.end()))
    return sorted(exclusion_spans, key=lambda x: x[0])

def is_in_exclusion(start: int, end: int, exclusion_spans: List[Tuple[int, int]]) -> bool:
    for es, ee in exclusion_spans:
        if not (end <= es or start >= ee):
            return True
    return False

def detect_pii_entities(text: str) -> List[Dict[str, Any]]:
    """Unified hybrid PII detection combining regex, contextual logic, and spaCy NER."""
    if not text:
        return []

    exclusion_spans = get_exclusion_spans(text)
    detected: List[PIIEntityMatch] = []

    # 1. Aadhaar Numbers
    for m in AADHAAR_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        cleaned = re.sub(r'[\s-]', '', m.group(0))
        is_valid_verhoeff = validate_verhoeff(cleaned)
        conf = 0.98 if is_valid_verhoeff else 0.85
        expl = "12-digit Indian National Aadhaar ID (Verhoeff checksum verified)" if is_valid_verhoeff else "12-digit potential Aadhaar pattern"
        detected.append(PIIEntityMatch(m.group(0), "AADHAAR", m.start(), m.end(), conf, expl))

    # 2. PAN Numbers
    for m in PAN_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        token = m.group(0)
        # Check 4th letter: Individual (P), Company (C), HUF (H), Firm (F), Trust (T), etc.
        fourth_char = token[3]
        conf = 0.95 if fourth_char in "PCHFATBLJG" else 0.80
        holder_type = "Individual" if fourth_char == 'P' else f"Entity type ({fourth_char})"
        detected.append(PIIEntityMatch(token, "PAN", m.start(), m.end(), conf, f"Indian Permanent Account Number (PAN) for {holder_type}"))

    # 3. Mobile Numbers
    for m in INDIAN_PHONE_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        raw_num = m.group(0).strip()
        # Avoid year confusion (e.g. 2021) or ordinary 10 digits that are part of section citations
        digits_only = re.sub(r'\D', '', raw_num)
        if len(digits_only) >= 10:
            detected.append(PIIEntityMatch(raw_num, "PHONE", m.start(), m.end(), 0.92, "Indian 10-digit mobile phone contact"))

    # 4. Landline Numbers
    for m in LANDLINE_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        token = m.group(0)
        # Verify STD prefix
        if len(re.sub(r'\D', '', token)) in range(8, 12):
            detected.append(PIIEntityMatch(token, "PHONE", m.start(), m.end(), 0.85, "Indian landline contact with STD area code"))

    # 5. Email Addresses
    for m in EMAIL_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        detected.append(PIIEntityMatch(m.group(0), "EMAIL", m.start(), m.end(), 0.98, "Electronic mail address identifier"))

    # 6. IFSC Codes
    for m in IFSC_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        token = m.group(0)
        detected.append(PIIEntityMatch(token, "IFSC", m.start(), m.end(), 0.94, f"Indian Financial System Code for bank branch: {token[:4]}"))

    # 7. UPI IDs
    for m in UPI_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        token = m.group(0)
        # Filter out common email domains
        if not re.search(r'\.(com|org|net|in|gov|edu|nic)$', token, re.IGNORECASE):
            detected.append(PIIEntityMatch(token, "UPI_ID", m.start(), m.end(), 0.90, "Unified Payments Interface (UPI) virtual payment address"))

    # 8. Vehicle Numbers
    for m in VEHICLE_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        token = m.group(0)
        # Indian state code validation
        state_codes = {"DL", "MH", "KA", "TN", "UP", "WB", "GJ", "RJ", "AP", "TS", "KL", "MP", "HR", "PB", "BR", "OD", "CH", "JK", "UK", "JH"}
        if token[:2].upper() in state_codes:
            detected.append(PIIEntityMatch(token, "VEHICLE_NUMBER", m.start(), m.end(), 0.93, f"Indian motor vehicle registration number ({token[:2]})"))

    # 9. Passport Numbers
    for m in PASSPORT_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        # Contextual check: passport keyword nearby
        ctx = text[max(0, m.start() - 40):min(len(text), m.end() + 40)].lower()
        if "passport" in ctx or "travel" in ctx:
            detected.append(PIIEntityMatch(m.group(0), "PASSPORT", m.start(), m.end(), 0.91, "Indian Passport document identifier"))

    # 10. Voter ID (EPIC)
    for m in VOTER_ID_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        ctx = text[max(0, m.start() - 40):min(len(text), m.end() + 40)].lower()
        if "voter" in ctx or "epic" in ctx or "election" in ctx:
            detected.append(PIIEntityMatch(m.group(0), "VOTER_ID", m.start(), m.end(), 0.92, "Election Commission Voter ID card"))

    # 11. Bank Account Numbers (Contextual)
    for m in re.finditer(r'\b\d{9,18}\b', text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        val = m.group(0)
        # Check if already tagged as Aadhaar or phone
        if any(d.start <= m.start() and d.end >= m.end() for d in detected):
            continue
        ctx = text[max(0, m.start() - 50):min(len(text), m.end() + 50)].lower()
        if any(kw in ctx for kw in BANK_ACCOUNT_KEYWORDS):
            detected.append(PIIEntityMatch(val, "BANK_ACCOUNT", m.start(), m.end(), 0.88, "Financial bank account number with contextual keyword"))

    # 12. Date of Birth and Age
    for m in DOB_AGE_REGEX.finditer(text):
        if is_in_exclusion(m.start(), m.end(), exclusion_spans):
            continue
        token = m.group(0)
        cat = "DATE_OF_BIRTH" if "born" in token.lower() or "dob" in token.lower() else "AGE"
        detected.append(PIIEntityMatch(token, cat, m.start(), m.end(), 0.90, f"Sensitive demographic identifier: {cat.replace('_', ' ')}"))

    # 13. Contextual Indian Residential Addresses
    for m in ADDRESS_TRIGGER_REGEX.finditer(text):
        start_idx = m.start()
        # Look ahead up to 140 chars for comma-delimited address tokens
        snippet = text[start_idx:min(len(text), start_idx + 150)]
        # Match address sentence/clause
        addr_match = re.search(r'^[^.;\n]+(?:Pin(?:\s*code)?[:\s-]*\d{6}|[A-Za-z\s]+-\s*\d{6}|district\s+[A-Za-z]+|distt\.?\s+[A-Za-z]+)?', snippet, re.IGNORECASE)
        if addr_match and len(addr_match.group(0).strip()) > 15:
            full_addr = addr_match.group(0).strip()
            end_idx = start_idx + len(full_addr)
            if not is_in_exclusion(start_idx, end_idx, exclusion_spans):
                detected.append(PIIEntityMatch(full_addr, "RESIDENTIAL_ADDRESS", start_idx, end_idx, 0.89, "Indian residential address structure containing locality, tehsil/district or pincode"))

    # 14. Named Entities: spaCy NER (if available) or Pure-Python Legal Pattern Recognizer
    if SPACY_AVAILABLE and nlp is not None:
        doc = nlp(text)
        for ent in doc.ents:
            if is_in_exclusion(ent.start_char, ent.end_char, exclusion_spans):
                continue
            if any(d.start <= ent.start_char and d.end >= ent.end_char for d in detected):
                continue
            if ent.label_ == "PERSON":
                cleaned_person = ent.text.strip()
                if len(cleaned_person) > 2 and not re.match(r'^(Section|Article|Court|Bench|State|Union|Police|Act|Order|Judgment)$', cleaned_person, re.IGNORECASE):
                    detected.append(PIIEntityMatch(cleaned_person, "PERSON_NAME", ent.start_char, ent.end_char, 0.86, "Named personal entity extracted via linguistic NER model"))
            elif ent.label_ in ("GPE", "LOC"):
                ctx = text[max(0, ent.start_char - 40):min(len(text), ent.end_char + 40)].lower()
                if any(re.search(r'\b' + kw, ctx) for kw in ['r/o', 'resident', 'village', 'native', 'district', 'distt', 'taluk', 'tehsil']):
                    detected.append(PIIEntityMatch(ent.text, "RESIDENTIAL_ADDRESS", ent.start_char, ent.end_char, 0.82, f"Geographical entity in residential address context ({ent.label_})"))

    # Pure-Python Legal Named Entity Recognizer (Domain patterns for Indian Legal Judgments)
    LEGAL_PERSON_PATTERNS = [
        re.compile(r'\b(?:Shri|Smt\.?|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Master|Baby)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b'),
        re.compile(r'\b(?:S/o|D/o|W/o|Son\s+of|Daughter\s+of|Wife\s+of)\s+(?:Shri|Late\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', re.IGNORECASE),
        re.compile(r'\b(?:PW|DW)[ -]?\d+[:\s-]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b'),
        re.compile(r'\b(?:Inspector|SI|I\.O\.|Investigating\s+Officer)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', re.IGNORECASE),
        re.compile(r'\b(?:complainant|victim|witness|accused)\s+(?:namely\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', re.IGNORECASE),
        re.compile(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})(?:,\s*(?:aged|residing|son|daughter|wife)|\s*\.{2,}\s*(?:Petitioner|Appellant|Respondent|Accused|Claimant))\b'),
        re.compile(r'\bJUSTICE\s+([A-Z][A-Z\s]+[A-Z])\b'),
    ]

    for pat in LEGAL_PERSON_PATTERNS:
        for m in pat.finditer(text):
            person_name = m.group(1).strip()
            span_start = m.start(1)
            span_end = m.end(1)
            if is_in_exclusion(span_start, span_end, exclusion_spans):
                continue
            if any(d.start <= span_start and d.end >= span_end for d in detected):
                continue
            if len(person_name) > 3 and not re.match(r'^(Section|Article|Court|Bench|State|Union|Police|Act|Order|Judgment)$', person_name, re.IGNORECASE):
                detected.append(PIIEntityMatch(person_name, "PERSON_NAME", span_start, span_end, 0.91, "Personal name identified via Indian legal structural and honorific patterns"))
    # 15. Role-labelled names in Indian legal documents
        role_name_pattern = re.compile(
        r'\b(?:Petitioner|Respondent|Appellant|Complainant|Accused|Victim|Witness)[ \t]*:[ \t]*'
        r'([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3})\b',
        re.IGNORECASE
    ) 
    for m in role_name_pattern.finditer(text):
        name = m.group(1)
        start, end = m.span(1)

        if not is_in_exclusion(start, end, exclusion_spans):
            detected.append(
                PIIEntityMatch(
                    name, "PERSON_NAME", start, end, 0.93,
                    "Personal name identified from legal party role"
                )
            )

    # 16. Residential addresses following 'resides at'
    residence_pattern = re.compile(
        r'\b(?:resides?\s+at|residing\s+at|lives?\s+at)\s+'
        r'(\d+[A-Za-z/-]*\s+[^.;\n]{5,100})',
        re.IGNORECASE
    )

    for m in residence_pattern.finditer(text):
        address = m.group(1).strip()
        start, end = m.span(1)

        if not is_in_exclusion(start, end, exclusion_spans):
            detected.append(
                PIIEntityMatch(
                    address, "RESIDENTIAL_ADDRESS", start, end, 0.90,
                    "Residential address identified from contextual phrase"
                )
            )
    # Resolve overlapping entities (keep highest confidence or widest span)
    resolved: List[PIIEntityMatch] = []
    detected.sort(key=lambda x: (x.start, -(x.end - x.start), -x.confidence))

    for entity in detected:
        is_overlapping = False
        for r in resolved:
            if not (entity.end <= r.start or entity.start >= r.end):
                is_overlapping = True
                break
        if not is_overlapping:
            resolved.append(entity)

    # Sort in textual order
    resolved.sort(key=lambda x: x.start)
    return [r.to_dict() for r in resolved]
