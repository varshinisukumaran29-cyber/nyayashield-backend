import os
import re
import hashlib
from typing import List, Dict, Any, Tuple
import pymupdf  # PyMuPDF
import docx
from app.config import EXPORTS_DIR

def generate_pseudonym_mapping(entities: List[Dict[str, Any]], style: str = "ROLE_BASED") -> Dict[str, str]:
    """Generates document-scoped consistent pseudonym mappings for entities."""
    mapping: Dict[str, str] = {}
    counters: Dict[str, int] = {}

    for ent in entities:
        text = ent["text"].strip()
        norm_key = text.lower()
        if norm_key in mapping:
            continue

        role = ent.get("predicted_role", "GENERAL_INDIVIDUAL")
        cat = ent.get("category", "PERSON_NAME")
        
        prefix = role
        if role == "GENERAL_INDIVIDUAL":
            prefix = cat

        counters[prefix] = counters.get(prefix, 0) + 1
        idx = counters[prefix]

        if style == "ROLE_BASED":
            if role == "VICTIM":
                alias = f"[VICTIM_{idx}]"
            elif role == "MINOR":
                alias = f"[MINOR_CHILD_{idx}]"
            elif role == "WITNESS":
                alias = f"[WITNESS_{idx}]"
            elif role == "PETITIONER":
                alias = f"[PETITIONER_{idx}]"
            elif role == "RESPONDENT":
                alias = f"[RESPONDENT_{idx}]"
            elif role == "ACCUSED":
                alias = f"[ACCUSED_{idx}]"
            elif role == "FAMILY_MEMBER":
                alias = f"[FAMILY_RELATION_{idx}]"
            elif cat == "RESIDENTIAL_ADDRESS":
                alias = f"[ADDRESS_{idx}]"
            elif cat in ("AADHAAR", "PAN", "BANK_ACCOUNT"):
                alias = f"[NATIONAL_ID_{idx}]"
            else:
                alias = f"[PERSON_{idx}]"
        elif style == "ALPHABETIC":
            letter = chr(ord('A') + (idx - 1) % 26)
            alias = f"[{prefix}_{letter}]"
        else:  # NUMBERED
            alias = f"[ANONYMOUS_{idx}]"

        mapping[norm_key] = alias

    return mapping

def apply_mask(text: str, category: str, mask_char: str = "*") -> str:
    """Applies contextual character masking while preserving format hints."""
    cleaned = text.strip()
    if category == "AADHAAR":
        digits = [c for c in cleaned if c.isdigit()]
        if len(digits) >= 12:
            return f"XXXX-XXXX-{cleaned[-4:]}"
        return f"{mask_char * 8}{cleaned[-4:]}"
    elif category == "PAN":
        if len(cleaned) == 10:
            return f"{cleaned[:2]}{mask_char * 6}{cleaned[-2:]}"
        return f"{cleaned[:1]}{mask_char * (len(cleaned) - 2)}{cleaned[-1:]}"
    elif category == "PHONE":
        if len(cleaned) >= 10:
            return f"{mask_char * 6}{cleaned[-4:]}"
        return f"{mask_char * len(cleaned)}"
    elif category == "EMAIL":
        parts = cleaned.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + (mask_char * (max(2, len(name) - 1)))
            return f"{masked_name}@{domain}"
        return f"{mask_char * len(cleaned)}"
    elif category == "BANK_ACCOUNT":
        if len(cleaned) >= 8:
            return f"XXXX-XXXX-{cleaned[-4:]}"
        return f"{mask_char * len(cleaned)}"
    elif category == "VEHICLE_NUMBER":
        if len(cleaned) >= 6:
            return f"{cleaned[:4]}-{mask_char * 4}-{cleaned[-2:]}"
        return f"{mask_char * len(cleaned)}"
    else:  # PERSON_NAME or other strings
        words = cleaned.split()
        masked_words = []
        for w in words:
            if len(w) > 2:
                masked_words.append(w[0] + (mask_char * (len(w) - 1)))
            else:
                masked_words.append(mask_char * len(w))
        return " ".join(masked_words)

def redact_text_content(
    original_text: str,
    approved_entities: List[Dict[str, Any]],
    pseudonym_mapping: Dict[str, str],
    mask_char: str = "*"
) -> str:
    """Produces sanitized text by applying the designated action (REDACT, MASK, PSEUDONYMIZE)."""
    # Sort entities in reverse order of start position to keep offsets intact
    sorted_entities = sorted(approved_entities, key=lambda x: x["start_char"], reverse=True)
    sanitized = original_text

    for ent in sorted_entities:
        action = ent.get("action", "REDACT")
        if action == "REVIEW":
            continue  # Do not redact if unreviewed

        start = ent["start_char"]
        end = ent["end_char"]
        text_val = ent["text"]
        cat = ent.get("category", "PERSON_NAME")

        if action == "REDACT":
            replacement = f"[{cat}_REDACTED]"
        elif action == "MASK":
            replacement = apply_mask(text_val, cat, mask_char)
        elif action == "PSEUDONYMIZE":
            norm_key = text_val.strip().lower()
            replacement = pseudonym_mapping.get(norm_key, f"[{cat}_PSEUDONYM]")
        else:
            replacement = f"[{cat}_REDACTED]"

        sanitized = sanitized[:start] + replacement + sanitized[end:]

    return sanitized

def redact_pdf_document(
    source_pdf_path: str,
    output_pdf_path: str,
    approved_entities: List[Dict[str, Any]],
    pseudonym_mapping: Dict[str, str]
) -> bool:
    """Executes genuine stream-level PDF redaction via PyMuPDF. Text is physically removed from the stream."""
    try:
        doc = pymupdf.open(source_pdf_path)
        
        # Build text search terms to redact
        search_terms = []
        for ent in approved_entities:
            action = ent.get("action", "REDACT")
            if action == "REVIEW":
                continue
            text_val = ent["text"].strip()
            if text_val and len(text_val) > 1:
                search_terms.append(text_val)

        # Remove duplicate search terms
        search_terms = list(set(search_terms))

        for page in doc:
            for term in search_terms:
                rects = page.search_for(term)
                for rect in rects:
                    # Genuine redaction annotation
                    page.add_redact_annot(rect, fill=(0.1, 0.1, 0.1))
            
            # Apply redactions - this permanently wipes underlying text characters and vector stream!
            page.apply_redactions()

        # Sanitize metadata (strip author, title, creator, producer)
        doc.set_metadata({
            "title": "Sanitized Judgment - NyayaShield AI",
            "author": "NyayaShield AI Redaction Engine",
            "subject": "Redacted Legal Record",
            "creator": "NyayaShield AI Privacy Preserving Pipeline",
            "producer": "PyMuPDF Genuine Redaction Engine",
        })

        # Save with garbage collection, deflation, and stream clean
        doc.save(output_pdf_path, garbage=4, deflate=True, clean=True)
        doc.close()
        return True
    except Exception as e:
        print(f"Error redacting PDF: {e}")
        return False

def redact_docx_document(
    source_docx_path: str,
    output_docx_path: str,
    approved_entities: List[Dict[str, Any]],
    pseudonym_mapping: Dict[str, str],
    mask_char: str = "*"
) -> bool:
    """Sanitizes a DOCX file by performing run-level text replacement."""
    try:
        doc = docx.Document(source_docx_path)
        
        # Replacement dict
        replace_dict = {}
        for ent in approved_entities:
            action = ent.get("action", "REDACT")
            if action == "REVIEW":
                continue
            text_val = ent["text"].strip()
            cat = ent.get("category", "PERSON_NAME")
            if action == "REDACT":
                replace_dict[text_val] = f"[{cat}_REDACTED]"
            elif action == "MASK":
                replace_dict[text_val] = apply_mask(text_val, cat, mask_char)
            elif action == "PSEUDONYMIZE":
                replace_dict[text_val] = pseudonym_mapping.get(text_val.lower(), f"[{cat}_ANON]")

        # Iterate paragraphs and runs
        for p in doc.paragraphs:
            for target_text, replacement in replace_dict.items():
                if target_text in p.text:
                    p.text = p.text.replace(target_text, replacement)

        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        for target_text, replacement in replace_dict.items():
                            if target_text in p.text:
                                p.text = p.text.replace(target_text, replacement)

        doc.save(output_docx_path)
        return True
    except Exception as e:
        print(f"Error redacting DOCX: {e}")
        return False
