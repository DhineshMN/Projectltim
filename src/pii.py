# src/pii.py
import re
try:
    # The phonenumbers library is great for validating phone numbers but is optional.
    # The code will still run and detect emails/cards if it's not installed.
    import phonenumbers
except ImportError:
    phonenumbers = None

# --- Regular Expression Patterns ---

# Matches common email formats.
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")

# Matches sequences of 13 to 19 digits, which may include spaces or hyphens.
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# --- Context Guard Patterns (to prevent false positives) ---

# Matches URLs to prevent detecting numbers within them as PII.
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+")

# Matches text within code blocks (```...``` or `...`) to ignore potential PII.
CODE_RE = re.compile(r"```.*?```|`[^`]*?`", re.S)

# Matches common ID-like prefixes (e.g., "order id:", "ticket #") to avoid flagging them.
ID_HINT = re.compile(r"(?i)\b(order|ticket|issue|id|ref)\b.{0,10}[:#]?\s*[A-Z0-9\-]{3,}")


def _overlaps(span, spans_to_check):
    """Checks if a given span (start, end) overlaps with any of the spans in the list."""
    (start, end) = span
    for (check_start, check_end) in spans_to_check:
        if not (end <= check_start or start >= check_end):
            return True
    return False

def _luhn_ok(card_number: str) -> bool:
    """Validates a credit card-like number using the Luhn algorithm checksum."""
    digits = [int(c) for c in re.sub(r"\D", "", card_number)]
    if not (13 <= len(digits) <= 19):
        return False
    
    checksum, is_alt = 0, False
    for d in digits[::-1]:
        if is_alt:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        is_alt = not is_alt
        
    return (checksum % 10) == 0

def detect_pii(text: str) -> list:
    """
    Detects PII in a string, respecting context guards.
    Returns a list of tuples: (KIND, (start, end), value).
    """
    if not isinstance(text, str):
        return []

    # 1. Find all guarded regions first.
    guarded_spans = [m.span() for m in URL_RE.finditer(text)] + \
                    [m.span() for m in CODE_RE.finditer(text)] + \
                    [m.span() for m in ID_HINT.finditer(text)]

    hits = []
    
    # 2. Detect Emails, skipping any found in guarded regions.
    for match in EMAIL_RE.finditer(text):
        if not _overlaps(match.span(), guarded_spans):
            hits.append(("EMAIL", match.span(), match.group(0)))

    # 3. Detect Phone numbers if the library is available.
    if phonenumbers:
        # A broad regex to find phone-like numbers.
        for match in re.finditer(r"\+?[0-9()\-.\s]{7,}", text):
            if _overlaps(match.span(), guarded_spans):
                continue
            try:
                # Attempt to parse the number, trying default and common regions.
                parsed_num = phonenumbers.parse(match.group(0), None)
                if phonenumbers.is_valid_number(parsed_num):
                    # Format to the standard E.164 format (e.g., +14155552671).
                    e164_format = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164)
                    hits.append(("PHONE", match.span(), e164_format))
            except Exception:
                # Ignore candidates that fail to parse.
                pass

    # 4. Detect Card numbers that pass the Luhn check.
    for match in CARD_RE.finditer(text):
        if _overlaps(match.span(), guarded_spans):
            continue
        digits_only = re.sub(r"\D", "", match.group(0))
        if _luhn_ok(digits_only):
            hits.append(("CARD", match.span(), digits_only))
            
    return hits

def redact(text: str, hits: list) -> str:
    """Redacts the detected PII from the original text."""
    if not hits:
        return text

    parts = []
    last_index = 0
    # Sort hits by their starting position to process them in order.
    for kind, (start, end), value in sorted(hits, key=lambda x: x[1][0]):
        # Append the text slice before the current PII hit.
        parts.append(text[last_index:start])
        
        # Append the appropriate redacted version of the PII.
        if kind == "EMAIL":
            local_part, _, domain = value.partition("@")
            parts.append(f"{local_part[:2]}***@{domain}")
        elif kind == "PHONE":
            digits = re.sub(r"\D", "", value)
            parts.append(f"+{'*' * (len(digits) - 4)}{digits[-2:]}" if len(digits) > 4 else "+******")
        elif kind == "CARD":
            parts.append(f"**** **** **** {value[-4:]}")
            
        last_index = end
    
    # Append any remaining text after the last PII hit.
    parts.append(text[last_index:])
    
    return "".join(parts)