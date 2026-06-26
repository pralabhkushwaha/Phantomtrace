"""
Homograph & typosquatting detector.

Three independent techniques are combined:
  1. Punycode / IDN decoding       -> catches xn-- domains hiding real Cyrillic/Greek text
  2. Confusable-character skeleton  -> catches mixed-script tricks (Cyrillic 'a' instead of Latin 'a')
  3. Edit-distance / pattern check  -> catches classic typosquats (paypaI.com, micr0soft.com, g00gle.com)

No external homoglyph library is required -- the confusable table below
covers the characters actually seen in real phishing campaigns (Cyrillic,
Greek, full-width Latin, and digit/letter substitutions).
"""

import re
from .brand_list import KNOWN_BRANDS

# Characters that render near-identically to a Latin letter/digit.
# Mapped to their ASCII "skeleton" equivalent for comparison.
CONFUSABLE_MAP = {
    # Cyrillic look-alikes
    "а": "a", "А": "a", "е": "e", "Е": "e", "о": "o", "О": "o",
    "р": "p", "Р": "p", "с": "c", "С": "c", "у": "y", "У": "y",
    "х": "x", "Х": "x", "і": "i", "І": "i", "ѕ": "s", "Ѕ": "s",
    "к": "k", "К": "k", "м": "m", "М": "m", "н": "h", "Н": "h",
    "т": "t", "Т": "t", "в": "b", "В": "b", "г": "r", "ё": "e",
    # Greek look-alikes
    "α": "a", "Α": "a", "ο": "o", "Ο": "o", "ρ": "p", "Ρ": "p",
    "ν": "v", "Ν": "n", "υ": "u", "Υ": "y", "ι": "i", "Ι": "i",
    "κ": "k", "Κ": "k", "τ": "t", "Τ": "t",
    # Full-width / other unicode look-alikes
    "ⅰ": "i", "ℓ": "l",
    # Digit <-> letter substitutions (classic leetspeak typosquats)
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}

PUNYCODE_PREFIX = "xn--"


def _to_skeleton(s: str) -> str:
    """Lower-case and fold every confusable character to its ASCII look-alike."""
    s = s.lower()
    return "".join(CONFUSABLE_MAP.get(ch, ch) for ch in s)


def _has_non_ascii(s: str) -> bool:
    return any(ord(ch) > 127 for ch in s)


def decode_punycode_label(label: str):
    """Decode a single punycode label (xn--...) to its unicode form. Returns None on failure."""
    if not label.lower().startswith(PUNYCODE_PREFIX):
        return None
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        try:
            import codecs
            return codecs.decode(label.encode("ascii"), "punycode").decode("utf-8", errors="replace")
        except Exception:
            return None


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance, implemented without external dependencies."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def _strip_tld(domain: str):
    """Split 'paypal.com' -> ('paypal', 'com'). Best-effort, no public-suffix-list dependency."""
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return domain, ""


def _split_tokens(name: str):
    """
    Split a domain's name part into meaningful tokens on any non-alphanumeric
    separator (-, _, .). This is what lets us catch compound attack domains
    such as 'linkedln-login.com' or 'paypal-security-update.com', where the
    brand name is only ONE segment of a longer string and a whole-string
    edit-distance comparison would dilute the match.
    """
    return [t for t in re.split(r"[^a-z0-9]+", name) if t]


def _confidence_for(candidate_skeleton: str, brand_skeleton: str):
    """Edit-distance-based confidence (0-100) between a candidate string and a brand skeleton."""
    if not candidate_skeleton or not brand_skeleton:
        return 0, None
    distance = levenshtein(candidate_skeleton, brand_skeleton)
    if distance == 0:
        return 100, 0
    max_len = max(len(brand_skeleton), len(candidate_skeleton), 1)
    confidence = max(0, round(100 - (distance / max_len) * 130))
    return confidence, distance


def analyze_domain(domain: str) -> dict:
    """
    Main entry point. Returns a dict:
      {
        domain, decoded_unicode, punycode_detected, mixed_script,
        digit_substitution, likely_impersonating, confidence, flags[]
      }
    """
    domain = domain.strip().lower()
    flags = []
    punycode_detected = False

    # 1. Punycode decode (per-label, domains can mix punycode + ascii labels)
    labels = domain.split(".")
    decoded_labels = []
    for label in labels:
        decoded = decode_punycode_label(label)
        if decoded:
            punycode_detected = True
            decoded_labels.append(decoded)
        else:
            decoded_labels.append(label)
    decoded_unicode = ".".join(decoded_labels)
    if punycode_detected:
        flags.append(f"Punycode/IDN domain detected -> displays as '{decoded_unicode}'")

    mixed_script = _has_non_ascii(decoded_unicode)
    if mixed_script:
        flags.append("Non-Latin (Cyrillic/Greek/etc.) characters used to mimic Latin letters")

    raw_name, tld = _strip_tld(domain)
    digit_substitution = any(c in "0134578" for c in raw_name) and any(c.isdigit() for c in raw_name)

    # A domain that IS a verified, known-legitimate brand domain cannot also be
    # "impersonating" some other brand in the list -- skip straight to a clean result.
    if domain in KNOWN_BRANDS:
        return {
            "domain": domain,
            "decoded_unicode": decoded_unicode if punycode_detected else None,
            "punycode_detected": punycode_detected,
            "mixed_script": mixed_script,
            "digit_substitution": digit_substitution,
            "edit_distance": None,
            "likely_impersonating": None,
            "impersonating_brand_name": None,
            "confidence": 0,
            "flags": flags + ["Domain matches a verified known-legitimate brand domain"],
        }

    # 2. Build a normalized "skeleton" (whole string + per-token) to compare against known brands
    full_skeleton, _ = _strip_tld(_to_skeleton(decoded_unicode))
    tokens = _split_tokens(full_skeleton)

    best_match = None
    best_confidence = 0
    best_distance = None
    best_specific_flags = []

    for brand_domain, brand_label in KNOWN_BRANDS.items():
        brand_name, brand_tld = _strip_tld(brand_domain)
        brand_skeleton = _to_skeleton(brand_name)
        specific_flags = []
        candidate_confidence = 0
        candidate_distance = None

        if domain == brand_domain:
            continue  # exact match to the real domain itself -> not a spoof

        # Strategy A: compare the WHOLE local-part to the brand (catches micr0soft.com, g00gle.com)
        whole_conf, whole_dist = _confidence_for(full_skeleton, brand_skeleton)
        if whole_conf > candidate_confidence:
            candidate_confidence, candidate_distance = whole_conf, whole_dist

        # Strategy B: compare each HYPHEN/DOT-SEPARATED TOKEN to the brand
        # (catches linkedln-login.com, faceb00k-login.com, micros0ft-security.com).
        # Very short brand skeletons (e.g. "x", "sbi") need a near-exact token match,
        # otherwise short strings produce noisy false positives.
        if len(brand_skeleton) >= 3:
            min_token_len = 3 if len(brand_skeleton) <= 4 else 4
            for token in tokens:
                if len(token) < min_token_len:
                    continue
                if len(brand_skeleton) <= 4 and token != brand_skeleton:
                    continue  # require exact match for very short brand names
                tok_conf, tok_dist = _confidence_for(token, brand_skeleton)
                if tok_conf > candidate_confidence:
                    candidate_confidence, candidate_distance = tok_conf, tok_dist

        if candidate_confidence == 0 and full_skeleton != brand_skeleton:
            continue

        # Boost: identical skeleton achieved only through a unicode/digit trick
        if full_skeleton == brand_skeleton and decoded_unicode != brand_domain:
            candidate_confidence = max(
                candidate_confidence,
                95 if (mixed_script or punycode_detected or digit_substitution) else 85,
            )

        # Extra-domain pattern: brand name appears as a *substring* of a longer unrelated domain
        if len(brand_skeleton) >= 4 and brand_skeleton in full_skeleton and full_skeleton != brand_skeleton:
            candidate_confidence = max(candidate_confidence, 70)
            specific_flags.append(f"Brand name '{brand_label}' embedded inside an unrelated domain")

        # Same brand name, different / look-alike TLD (.cm, .co, .net instead of .com)
        if full_skeleton == brand_skeleton and tld != brand_tld:
            candidate_confidence = max(candidate_confidence, 80)
            specific_flags.append(f"Correct brand name but wrong TLD ('.{tld}' instead of '.{brand_tld}')")

        # Suspicious suffix word commonly used to lend false legitimacy
        suffix_words = {"login", "secure", "security", "verify", "verification", "support",
                         "update", "account", "alert", "service", "id", "auth"}
        if tokens and len(tokens) > 1 and any(t in suffix_words for t in tokens) and candidate_confidence >= 60:
            specific_flags.append(
                "Brand name combined with a trust-signalling word (e.g. 'login'/'secure'/'support') "
                "to look like an official sub-service"
            )

        if candidate_confidence > best_confidence:
            best_confidence = candidate_confidence
            best_match = brand_domain
            best_distance = candidate_distance
            best_specific_flags = specific_flags

    result = {
        "domain": domain,
        "decoded_unicode": decoded_unicode if punycode_detected else None,
        "punycode_detected": punycode_detected,
        "mixed_script": mixed_script,
        "digit_substitution": digit_substitution,
        "edit_distance": best_distance,
        "likely_impersonating": None,
        "impersonating_brand_name": None,
        "confidence": 0,
        "flags": flags,
    }

    # Only report a match above a sane confidence floor to avoid noisy false positives
    if best_match and best_confidence >= 55:
        result["likely_impersonating"] = best_match
        result["impersonating_brand_name"] = KNOWN_BRANDS[best_match]
        result["confidence"] = min(best_confidence, 99)
        result["flags"].extend(best_specific_flags)

    return result
