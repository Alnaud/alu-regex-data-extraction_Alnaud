"""
ALU Regex Data Extraction & Secure Validation
=============================================

Reads raw, messy text (simulating an external API dump), extracts four
structured data types with regex, validates them, and writes a safe,
structured JSON report.

Data types extracted:
    1. Email addresses (including ALU-specific sub-classifications)
    2. Credit card numbers (format-checked + Luhn-validated + masked)
    3. Phone numbers (multiple international/local formats)
    4. URLs (http/https only)

Security posture:
    - Input is treated as UNTRUSTED. Before any extraction happens, the raw
      text is scanned for known attack patterns (script injection,
      javascript: pseudo-protocol, SQL-injection style strings).
    - Anything that overlaps a flagged malicious region is NOT extracted as
      "safe" data (e.g. a URL sitting inside a <script> tag is reported as
      a security flag, not as a normal URL).
    - We never eval(), exec(), or otherwise execute anything found in the
      input.
    - Credit card numbers are masked before they ever reach the JSON output
      or the console. Full numbers are held only in memory, briefly, for
      the Luhn check.
    - Anything we print or write to file is first passed through
      sanitize_for_output(), which strips control characters and truncates
      length, so hostile text can't corrupt logs or downstream JSON
      consumers.

Run:
    python src/main.py
(See README.md for details.)
"""

import json
import os
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# NOTE ON REALISM: a fully correct implementation of email/phone/URL
# validation would need dedicated libraries (e.g. a phone-number library
# that knows every country's numbering plan). This assignment is scoped to
# regex-based extraction, so the patterns below are deliberately practical
# rather than exhaustive -- limitations are called out in comments and in
# the README.
# ---------------------------------------------------------------------------


# ============================================================================
# SECURITY: patterns that indicate the input is trying to do something other
# than just "be data" (script injection, protocol smuggling, SQL injection).
# These are checked FIRST, before any "normal" extraction happens.
# ============================================================================
SECURITY_PATTERNS = [
    ("script_tag", re.compile(r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL)),
    ("event_handler_attr", re.compile(r'\bon\w+\s*=\s*["\'][^"\']*["\']', re.IGNORECASE)),
    ("js_pseudo_protocol", re.compile(r"\bjavascript\s*:", re.IGNORECASE)),
    (
        "sql_injection_like",
        re.compile(
            r"(;\s*--)|(--\s*$)|(\bDROP\s+TABLE\b)|(\bUNION\s+SELECT\b)|(\bOR\s+1\s*=\s*1\b)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
]

# Generic HTML tag detector, used only to strip/neutralize tags that show up
# inside otherwise-legitimate text (not itself a "data type" we extract).
HTML_TAG_REGEX = re.compile(r"</?[a-zA-Z][^<>]*>")


def find_security_flags(text):
    """
    Scan the ENTIRE raw text for known attack patterns before we trust any
    of it. Returns a list of flags, each with the character span so later
    extraction steps can avoid pulling "clean-looking" data out of a
    malicious region (e.g. a URL that only exists inside a <script> tag).
    """
    flags = []
    for label, pattern in SECURITY_PATTERNS:
        for m in pattern.finditer(text):
            flags.append(
                {
                    "type": label,
                    "span": (m.start(), m.end()),
                    # Truncate + sanitize before we ever store/print it.
                    "snippet": sanitize_for_output(m.group(0), max_len=80),
                }
            )
    return flags


def overlaps_flagged_region(start, end, flags):
    """True if [start, end) overlaps any security-flagged span."""
    for f in flags:
        f_start, f_end = f["span"]
        if start < f_end and end > f_start:
            return True
    return False


def sanitize_for_output(value, max_len=200):
    """
    Defensive helper used on anything derived from untrusted input before it
    is printed to the console or written to JSON. Strips control/ non
    printable characters (which could otherwise be used for log injection /
    terminal escape tricks) and truncates overly long values.
    """
    if value is None:
        return value
    # Remove ASCII control characters (0x00-0x1F, 0x7F) except plain spaces.
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value)
    cleaned = cleaned.strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "...(truncated)"
    return cleaned


# ============================================================================
# 1. EMAIL ADDRESSES  (general + ALU-specific classification)
# ============================================================================
# Local part: must start with an alphanumeric char, then allow the usual
# RFC-5322-ish "safe" characters. Domain: standard dot-separated labels plus
# a final TLD of 2+ letters. Lookaround guards stop us from matching only
# *part* of a longer, malformed run of characters (e.g. "broken@@email.com").
EMAIL_REGEX = re.compile(
    r"(?<![\w.+-])"                                   # not preceded by an email-ish char
    r"[A-Za-z0-9][A-Za-z0-9._%+-]*"                   # local part
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"       # first domain label
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"  # additional domain labels
    r"\.[A-Za-z]{2,}"                                 # TLD
    r"(?![\w.+-])"                                    # not followed by an email-ish char
)

# ALU-specific domains. Checked with $ anchors against the *domain only*,
# case-insensitive (so "aluEducation.com" still validates), and checked
# from most-specific to least-specific so "alumni.alueducation.com" is never
# mis-classified as a generic "@alueducation.com" official address.
ALU_ALUMNI_DOMAIN = re.compile(r"^alumni\.alueducation\.com$", re.IGNORECASE)
ALU_SI_DOMAIN = re.compile(r"^si\.alueducation\.com$", re.IGNORECASE)
ALU_OFFICIAL_DOMAIN = re.compile(r"^alueducation\.com$", re.IGNORECASE)


def classify_email(email):
    """Return an ALU category, or 'general' for any other well-formed email."""
    domain = email.split("@", 1)[1]
    if ALU_ALUMNI_DOMAIN.match(domain):
        return "alu_alumni"
    if ALU_SI_DOMAIN.match(domain):
        return "alu_si"
    if ALU_OFFICIAL_DOMAIN.match(domain):
        return "alu_official"
    return "general"


def extract_emails(text, flags):
    results = []
    for m in EMAIL_REGEX.finditer(text):
        if overlaps_flagged_region(m.start(), m.end(), flags):
            continue  # don't trust "emails" sitting inside a flagged payload
        email = m.group(0)
        results.append({"value": email, "category": classify_email(email)})
    return results


# ============================================================================
# 2. CREDIT CARD NUMBERS (format check + Luhn validation + masking)
# ============================================================================
# Matches 16 digits grouped as 4-4-4-4, separated consistently by spaces,
# dashes, or nothing. This intentionally will NOT match something like
# "1234-56-78" (wrong grouping / too few digits), which the assignment asks
# us to reject.
CREDIT_CARD_REGEX = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")


def luhn_is_valid(digits):
    """Standard Luhn checksum used by all major card networks."""
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mask_card(digits):
    """Never expose the full number: keep only the last 4 digits."""
    return "**** **** **** " + digits[-4:]


def extract_credit_cards(text, flags):
    results = []
    card_spans = []
    for m in CREDIT_CARD_REGEX.finditer(text):
        if overlaps_flagged_region(m.start(), m.end(), flags):
            continue
        card_spans.append((m.start(), m.end()))
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        results.append(
            {
                # SECURITY: only the masked form ever leaves this function.
                "masked": mask_card(digits),
                "luhn_valid": luhn_is_valid(digits),
            }
        )
    return results, card_spans


# ============================================================================
# 3. PHONE NUMBERS (realistic, messy, international + local formats)
# ============================================================================
# We deliberately extract broadly (digits, spaces, dots, dashes, parens,
# leading +) and then validate by counting digits, rather than trying to
# write one regex per country's numbering plan (that's a job for a proper
# phone-number library, not raw regex). An optional "ext./x <digits>"
# suffix is captured separately.
PHONE_REGEX = re.compile(
    r"(?<!\w)"
    r"(\+?\(?\d[\d\s().-]{6,17}\d)"          # main number candidate
    r"(?:\s*(?:ext\.?|x)\s*(\d{1,5}))?"      # optional extension
    r"(?!\w)",
    re.IGNORECASE,
)


def extract_phones(text, flags, card_spans=()):
    results = []
    for m in PHONE_REGEX.finditer(text):
        if overlaps_flagged_region(m.start(), m.end(), flags):
            continue
        if overlaps_flagged_region(m.start(), m.end(), [{"span": s} for s in card_spans]):
            continue  # already classified as a credit card number, don't double-count
        raw_number, ext = m.group(1), m.group(2)
        digit_count = len(re.sub(r"\D", "", raw_number))
        # E.164 allows a max of 15 digits; we require at least 7 so we don't
        # pick up short unrelated numbers (ticket numbers, years, etc.).
        is_valid_length = 7 <= digit_count <= 15
        results.append(
            {
                "value": raw_number.strip(),
                "extension": ext,
                "digit_count": digit_count,
                "plausible_length": is_valid_length,
            }
        )
    return results


# ============================================================================
# 4. URLS (http/https only -- explicitly excludes javascript: etc.)
# ============================================================================
# Requiring the literal http:// or https:// scheme automatically excludes
# dangerous pseudo-protocols like "javascript:alert(...)" from ever being
# treated as a URL, without needing extra logic here.
URL_REGEX = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)


def extract_urls(text, flags):
    results = []
    for m in URL_REGEX.finditer(text):
        url = m.group(0)
        # Trim common trailing punctuation that regex greediness can pick up
        # (e.g. a URL immediately followed by a period or closing bracket).
        trimmed = re.sub(r"[.,;:)\]]+$", "", url)
        end = m.start() + len(trimmed)
        if overlaps_flagged_region(m.start(), end, flags):
            # e.g. a URL that only appears inside a <script> tag payload.
            continue
        results.append({"value": trimmed})
    return results


# ============================================================================
# ORCHESTRATION
# ============================================================================
def analyze(text):
    security_flags = find_security_flags(text)
    credit_cards, card_spans = extract_credit_cards(text, security_flags)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "security_flags": security_flags,
        "emails": extract_emails(text, security_flags),
        "credit_cards": credit_cards,
        "phone_numbers": extract_phones(text, security_flags, card_spans),
        "urls": extract_urls(text, security_flags),
    }


def print_console_summary(report):
    """
    Console output intentionally shows COUNTS and MASKED values only.
    Full email addresses are shown (they're the extracted product this
    program is meant to verify) but credit cards stay masked everywhere,
    and no raw flagged/malicious text is ever printed in full.
    """
    print("=" * 60)
    print("ALU Regex Data Extraction - Summary")
    print("=" * 60)

    print(f"\nSecurity flags detected: {len(report['security_flags'])}")
    for f in report["security_flags"]:
        print(f"  - [{f['type']}] {f['snippet']}")

    print(f"\nEmails found: {len(report['emails'])}")
    for e in report["emails"]:
        print(f"  - {e['value']}  ({e['category']})")

    print(f"\nCredit cards found: {len(report['credit_cards'])}")
    for c in report["credit_cards"]:
        status = "Luhn OK" if c["luhn_valid"] else "Luhn FAILED"
        print(f"  - {c['masked']}  ({status})")

    print(f"\nPhone numbers found: {len(report['phone_numbers'])}")
    for p in report["phone_numbers"]:
        status = "plausible" if p["plausible_length"] else "implausible length"
        ext_note = f" ext {p['extension']}" if p["extension"] else ""
        print(f"  - {p['value']}{ext_note}  ({status}, {p['digit_count']} digits)")

    print(f"\nURLs found: {len(report['urls'])}")
    for u in report["urls"]:
        print(f"  - {u['value']}")

    print("\n" + "=" * 60)


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    report = analyze(raw_text)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print_console_summary(report)
    print(f"\nFull JSON report written to: {output_path}")


if __name__ == "__main__":
    main()
