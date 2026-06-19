"""
Attachment risk analyzer.

Works on the parsed email.message.Message object (from header_analyzer.parse_eml)
and also exposes analyze_filename() standalone so the web UI / CLI can check a
single filename the user pastes in directly.
"""

import re

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
    "ws", "wsf", "wsh", "msi", "msp", "ps1", "ps1xml", "ps2", "psc1",
    "lnk", "hta", "apk", "jar", "reg", "vb", "vbscript", "iso", "img",
}

# Containers that are not dangerous on their own but are routinely used
# to smuggle a dangerous payload past basic mail-gateway filters.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso", "img", "gz", "tar"}

SUSPICIOUS_NAME_KEYWORDS = [
    "invoice", "receipt", "payment", "bank", "kyc", "update", "urgent",
    "statement", "refund", "order", "delivery", "tracking", "document",
    "scan", "important", "verify", "verification", "salary", "bonus",
]

DOUBLE_EXT_RE = re.compile(
    r"\.([a-z0-9]{2,5})\.(" + "|".join(DANGEROUS_EXTENSIONS) + r")$", re.IGNORECASE
)


def _get_ext(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def analyze_filename(filename: str, content_type: str = "") -> dict:
    filename_clean = (filename or "").strip()
    ext = _get_ext(filename_clean)
    flags = []
    score = 0

    double_ext_match = DOUBLE_EXT_RE.search(filename_clean)
    if double_ext_match:
        flags.append(
            f"Double Extension Detected ('.{double_ext_match.group(1)}.{double_ext_match.group(2)}') "
            f"— designed to look like a harmless file in preview"
        )
        score += 35

    if ext in DANGEROUS_EXTENSIONS:
        flags.append(f"Dangerous executable-type extension: .{ext}")
        score += 30

    if ext in ARCHIVE_EXTENSIONS and not double_ext_match:
        flags.append(f"Archive format ('.{ext}') — can hide an executable payload inside")
        score += 10

    matched_keywords = [kw for kw in SUSPICIOUS_NAME_KEYWORDS if kw in filename_clean.lower()]
    if matched_keywords and (ext in DANGEROUS_EXTENSIONS or double_ext_match):
        flags.append(
            f"Social-engineering filename pattern (keyword(s): {', '.join(matched_keywords)}) "
            f"combined with a dangerous extension"
        )
        score += 15

    # MIME type vs extension mismatch
    if content_type:
        declared = content_type.split("/")[-1].lower()
        if ext and declared and ext not in declared and declared not in ext:
            # only flag meaningful mismatches, e.g. declared pdf but ext is exe
            if ext in DANGEROUS_EXTENSIONS or double_ext_match:
                flags.append(f"MIME type mismatch: declared as '{content_type}' but filename ends in .{ext}")
                score += 15

    score = min(score, 100)
    return {
        "filename": filename_clean,
        "extension": ext,
        "is_dangerous_extension": ext in DANGEROUS_EXTENSIONS,
        "is_double_extension": bool(double_ext_match),
        "flags": flags,
        "risk_score": score,
    }


def analyze_attachments(msg) -> dict:
    """msg is an email.message.Message (already parsed)."""
    results = []
    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if filename or "attachment" in content_disposition.lower():
            if not filename:
                continue
            content_type = part.get_content_type()
            results.append(analyze_filename(filename, content_type))

    overall_score = max((r["risk_score"] for r in results), default=0)
    return {
        "attachments": results,
        "count": len(results),
        "overall_risk_score": overall_score,
        "has_dangerous_attachment": any(r["risk_score"] >= 30 for r in results),
    }
