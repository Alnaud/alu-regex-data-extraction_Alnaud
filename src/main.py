"""
ALU Regex Data Extraction & Validation Project
================================================

This script reads a messy block of text (kind of like a fake dump of data
we'd get from an API or a scraped webpage) and pulls out 4 kinds of info
using regex:
    1. Emails (and I also sort ALU emails into categories)
    2. Credit card numbers (I check the format, run Luhn's algorithm on
       them, and then mask them so the real number is never shown)
    3. Phone numbers (lots of different formats, so this is not perfect)
    4. URLs (only http/https, nothing else)

I also added a very basic "security check" step before doing any of the
real extraction. The idea is: don't trust the input text. So before I even
look for emails/cards/etc, I scan the whole text for things that look like
script tags, javascript: links, or SQL injection style text. If a piece of
text overlaps with one of those flagged areas, I don't extract it as normal
data - I just count it as a security flag instead.

A few notes on why I did things a certain way:
    - I never use eval() or exec() on anything from the input text. That
      would be a huge security risk.
    - Credit card numbers get masked (**** **** **** 1234) before they are
      ever printed or saved to the JSON file. The full number only exists
      in memory for a split second while I check Luhn's algorithm.
    - Anything that gets printed/saved goes through a small "cleanup"
      function first (sanitize_for_output) that removes weird control
      characters and cuts off text that's too long. This is just to stop
      someone from injecting weird escape codes into my logs or JSON.

How to run it:
    python src/main.py
(more info is in the README.md)
"""

import json
import os
import re
from datetime import datetime, timezone

# Just a heads up: doing PERFECT email/phone/URL validation is really hard
# and usually needs a dedicated library (there are whole libraries just for
# validating phone numbers per country). Since this assignment is about
# practicing regex, my patterns below are "good enough" for the test data,
# SECURITY CHECK STEP
# Before I trust the text enough to pull "real" data out of it, I scan the
# WHOLE thing for patterns that look malicious (script injection, the
# javascript: pseudo protocol, and SQL-injection-looking strings).

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

# Not really one of the "4 data types" we need to extract, just a helper
# regex in case I need to strip stray HTML tags out of otherwise normal text.
HTML_TAG_REGEX = re.compile(r"</?[a-zA-Z][^<>]*>")


def find_security_flags(text):
    """
    Goes through the whole raw text and looks for the "attack-looking"
    patterns defined above. Returns a list of flags with the start/end
    position of each match, so that later, when I'm extracting emails/URLs/
    etc, I can skip anything that overlaps with one of these flagged spots.
    (For example, if there's a URL hiding inside a <script> tag, I don't
    want to report that as a normal, safe URL.)
    """
    flags = []
    for label, pattern in SECURITY_PATTERNS:
        for m in pattern.finditer(text):
            flags.append(
                {
                    "type": label,
                    "span": (m.start(), m.end()),
                    # clean it up before saving/printing, just in case
                    "snippet": sanitize_for_output(m.group(0), max_len=80),
                }
            )
    return flags


def overlaps_flagged_region(start, end, flags):
    """Quick helper: does [start, end) overlap with any flagged span?"""
    for f in flags:
        f_start, f_end = f["span"]
        if start < f_end and end > f_start:
            return True
    return False


def sanitize_for_output(value, max_len=200):
    """
    Small helper I use anywhere I'm about to print or save something that
    came from the untrusted input text. It strips out control characters
    (which could otherwise mess with the terminal or be used for some kind
    of log injection trick) and cuts the string short if it's too long.
    """
    if value is None:
        return value
    # get rid of ASCII control characters (0x00-0x1F and 0x7F)
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value)
    cleaned = cleaned.strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "...(truncated)"
    return cleaned


# 1. EMAIL ADDRESSES  (general emails + ALU-specific categories)
# The local part (before the @) has to start with a letter/number, then can
# have the usual email-safe characters. The domain part is normal
# dot-separated labels, ending in a TLD of 2+ letters. The lookaround stuff
# at the start/end is just there so I don't accidentally match half of a
# broken email like "broken@@email.com".
EMAIL_REGEX = re.compile(
    r"(?<![\w.+-])"                                   # don't start matching in the middle of an email
    r"[A-Za-z0-9][A-Za-z0-9._%+-]*"                   # local part (before the @)
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"       # first domain label
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"  # any more domain labels
    r"\.[A-Za-z]{2,}"                                 # the TLD (.com, .edu, etc)
    r"(?![\w.+-])"                                    # don't stop matching in the middle either
)

# These are the ALU-specific domains I need to recognize. I check them from
# most specific to least specific (alumni/si before the general official
# domain) so something like "alumni.alueducation.com" doesn't accidentally
# get labeled as just a plain "@alueducation.com" address.
ALU_ALUMNI_DOMAIN = re.compile(r"^alumni\.alueducation\.com$", re.IGNORECASE)
ALU_SI_DOMAIN = re.compile(r"^si\.alueducation\.com$", re.IGNORECASE)
ALU_OFFICIAL_DOMAIN = re.compile(r"^alueducation\.com$", re.IGNORECASE)


def classify_email(email):
    """Figures out which ALU category an email belongs to (or 'general')."""
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
            continue  # this "email" is inside a flagged/malicious chunk, skip it
        email = m.group(0)
        results.append({"value": email, "category": classify_email(email)})
    return results


# CREDIT CARD NUMBERS (check format + run Luhn's algorithm + mask it)
# I'm looking for 16 digits grouped in 4s (4-4-4-4), separated by spaces,
# dashes, or nothing at all. On purpose, this will NOT match weird stuff
# like "1234-56-78" since that's not grouped correctly and doesn't have
# enough digits anyway.
CREDIT_CARD_REGEX = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")


def luhn_is_valid(digits):
    """This is just the standard Luhn checksum that credit card companies use."""
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
    """We should never show the full card number, so just keep the last 4."""
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
                # only the masked version ever leaves this function, on purpose
                "masked": mask_card(digits),
                "luhn_valid": luhn_is_valid(digits),
            }
        )
    return results, card_spans
# PHONE NUMBERS (messy, mixed international + local formats)
#  Instead of trying to write a separate regex for every single country's
# phone number format (which honestly sounds miserable), I just grab
# anything that LOOKS like a phone number (digits, spaces, dots, dashes,
# parentheses, maybe a leading +) and then decide if it's "plausible" based
# on how many digits it has. I also grab an optional extension like "ext. 123"
# or "x123" if there is one.
PHONE_REGEX = re.compile(
    r"(?<!\w)"
    r"(\+?\(?\d[\d\s().-]{6,17}\d)"          # the main phone number part
    r"(?:\s*(?:ext\.?|x)\s*(\d{1,5}))?"      # optional extension, e.g. ext. 123
    r"(?!\w)",
    re.IGNORECASE,
)


def extract_phones(text, flags, card_spans=()):
    results = []
    for m in PHONE_REGEX.finditer(text):
        if overlaps_flagged_region(m.start(), m.end(), flags):
            continue
        if overlaps_flagged_region(m.start(), m.end(), [{"span": s} for s in card_spans]):
            continue  # this was already grabbed as a credit card, don't count it twice
        raw_number, ext = m.group(1), m.group(2)
        digit_count = len(re.sub(r"\D", "", raw_number))
        # real phone numbers max out at 15 digits (E.164 standard), and I
        # want at least 7 so I don't accidentally grab random short numbers
        # like a ticket number or a year
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
# URLS (only http/https, nothing else counts)
# By only matching things that literally start with http:// or https://, I
# automatically ignore dangerous stuff like "javascript:alert(...)" without
# having to write any extra logic for it.
URL_REGEX = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)


def extract_urls(text, flags):
    results = []
    for m in URL_REGEX.finditer(text):
        url = m.group(0)
        # regex tends to be a little too greedy, so I trim off trailing
        # punctuation that's probably not actually part of the URL
        # (like a period right after a link at the end of a sentence)
        trimmed = re.sub(r"[.,;:)\]]+$", "", url)
        end = m.start() + len(trimmed)
        if overlaps_flagged_region(m.start(), end, flags):
            # e.g. this URL only shows up because it's inside a <script> tag
            continue
        results.append({"value": trimmed})
    return results


# Putted it all together

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
    Prints a quick summary to the console. I show full emails since that's
    the whole point of this program, but credit cards always stay masked,
    and I never print the full text of anything flagged as malicious.
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
    # figuring out where the input/output files live relative to this script
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
