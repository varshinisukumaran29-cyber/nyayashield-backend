import os
import re
from typing import Dict, Any, Tuple
import pymupdf  # PyMuPDF
import docx

def extract_metadata_from_text(text: str) -> Dict[str, Any]:
    """Heuristically extracts Indian court name, case number, and case title from header text."""
    court_match = re.search(r'(IN THE (?:SUPREME COURT OF INDIA|HIGH COURT OF [A-Za-z\s]+|DISTRICT COURT[A-Za-z\s]+))', text, re.IGNORECASE)
    court_name = court_match.group(1).strip() if court_match else None

    case_match = re.search(r'((?:CRL\.?A\.?|CRIMINAL APPEAL|W\.?P\.?|WRIT PETITION|SLP|BAIL APPLN\.?|C\.?S\.?|MAT\.?APP\.?)\s*(?:\([A-Za-z]+\))?\s*(?:NO\.?|NUMBER)?\s*\d+[\s/OF]+\d{2,4})', text, re.IGNORECASE)
    case_number = case_match.group(1).strip() if case_match else None

    # Title match (e.g., Party A ... Petitioner Versus Party B ... Respondent)
    title_match = re.search(r'([A-Za-z\s.,]+(?:\.{2,}|…)\s*(?:Petitioner|Appellant).*?(?:Versus|Vs\.?|V\.).*?[A-Za-z\s.,]+(?:\.{2,}|…)\s*(?:Respondent|Accused))', text[:2000], re.IGNORECASE | re.DOTALL)
    case_title = re.sub(r'\s+', ' ', title_match.group(1)).strip() if title_match else None

    return {
        "court_name": court_name,
        "case_number": case_number,
        "case_title": case_title,
    }

def process_pdf(file_path: str) -> Dict[str, Any]:
    """Extracts text, page count, and evaluates scanned status for PDF."""
    doc = pymupdf.open(file_path)
    page_count = len(doc)
    full_text_list = []
    scanned_pages = 0

    for i, page in enumerate(doc):
        page_text = page.get_text()
        full_text_list.append(page_text)
        # If page has fewer than 40 characters and has images, it may be scanned
        if len(page_text.strip()) < 40:
            image_list = page.get_images()
            if len(image_list) > 0:
                scanned_pages += 1

    doc.close()
    full_text = "\n\n--- PAGE BREAK ---\n\n".join(full_text_list)
    is_scanned = (scanned_pages / max(1, page_count)) > 0.5

    meta = extract_metadata_from_text(full_text)
    return {
        "text_content": full_text,
        "page_count": page_count,
        "is_scanned": is_scanned,
        "scanned_page_ratio": round(scanned_pages / max(1, page_count), 2),
        **meta
    }

def process_docx(file_path: str) -> Dict[str, Any]:
    """Extracts text and metadata from DOCX."""
    doc = docx.Document(file_path)
    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
    full_text = "\n\n".join(paragraphs)
    
    # Rough page estimate (~400 words per page)
    word_count = len(full_text.split())
    page_count = max(1, round(word_count / 400))

    meta = extract_metadata_from_text(full_text)
    return {
        "text_content": full_text,
        "page_count": page_count,
        "is_scanned": False,
        "scanned_page_ratio": 0.0,
        **meta
    }

def process_txt(file_path: str) -> Dict[str, Any]:
    """Extracts text and metadata from TXT."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        full_text = f.read()

    word_count = len(full_text.split())
    page_count = max(1, round(word_count / 400))
    meta = extract_metadata_from_text(full_text)
    return {
        "text_content": full_text,
        "page_count": page_count,
        "is_scanned": False,
        "scanned_page_ratio": 0.0,
        **meta
    }
