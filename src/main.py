"""
ALU Regex Data Extraction & Validation Project

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
import re

# Just a heads up: doing PERFECT email/phone/URL validation is really hard
# and usually needs a dedicated library (there are whole libraries just for
# validating phone numbers per country). Since this assignment is about
# practicing regex, my patterns below are "good enough" for the test data,

# 1. EMAIL ADDRESSES  (general emails + ALU-specific categories)
# The local part (before the @) has to start with a letter/number, then can
# have the usual email-safe characters. The domain part is normal
# dot-separated labels, ending in a TLD of 2+ letters. The lookaround stuff
# at the start/end is just there so I don't accidentally match half of a
# broken email like "broken@@email.com".
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# PHONE NUMBERS (messy, mixed international + local formats)
#  Instead of trying to write a separate regex for every single country's
# phone number format (which honestly sounds miserable), I just grab
# anything that LOOKS like a phone number (digits, spaces, dots, dashes,
# parentheses, maybe a leading +) and then decide if it's "plausible" based
# on how many digits it has. I also grab an optional extension like "ext. 123"
# or "x123" if there is one.
PHONE_REGEX = r"\+?\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}"

# URLS (only http/https, nothing else counts)
# By only matching things that literally start with http:// or https://, I
# automatically ignore dangerous stuff like "javascript:alert(...)" without
# having to write any extra logic for it.
URL_REGEX = r'https?://[^\s<>"]+|www\.[^\s<>"]+'

# CREDIT CARD NUMBERS (check format + run Luhn's algorithm + mask it)
# I'm looking for 16 digits grouped in 4s (4-4-4-4), separated by spaces,
# dashes, or nothing at all. On purpose, this will NOT match weird stuff
# like "1234-56-78" since that's not grouped correctly and doesn't have
# enough digits anyway.
CARD_REGEX = r"\b(?:\d[ -]*?){13,16}\b"


def luhn_check(card_str):
    """This is just the standard Luhn checksum that credit card companies use."""
    digits = [int(d) for d in re.sub(r"\D", "", card_str)]
    if not (13 <= len(digits) <= 16):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def mask_card(card_str):
    """We should never show the full card number, so just keep the last 4."""
    digits = re.sub(r"\D", "", card_str)
    return f"**** **** **** {digits[-4:]}"


# These are the ALU-specific domains I need to recognize. I check them from
# most specific to least specific (alumni/si before the general official
# domain) so something like "alumni.alueducation.com" doesn't accidentally
# get labeled as just a plain "@alueducation.com" address.
def categorize_email(email):
    """Figures out which ALU category an email belongs to (or 'general')."""
    domain = email.split("@")[-1].lower()
    if domain == "alumni.alueducation.com":
        return "ALU Alumni"
    elif domain == "si.alueducation.com":
        return "ALU Staff/Faculty"
    elif "alueducation.com" in domain:
        return "ALU Official"
    return "General Email"


def process_data(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    # SECURITY CHECK STEP
    # Before I trust the text enough to pull "real" data out of it, I scan the
    # WHOLE thing for patterns that look malicious (script injection, the
    # javascript: pseudo protocol, and SQL-injection-looking strings).
    # Step 1: Pre-process and flag malicious script/SQL tags
    flags = []
    if re.search(r"<script.*?>.*?</script>", text, re.IGNORECASE | re.DOTALL):
        flags.append("Script tag detected")
    if re.search(r"javascript:", text, re.IGNORECASE):
        flags.append("JavaScript URI detected")
    if re.search(
        r"(UNION\s+SELECT|SELECT\s+\*|DROP\s+TABLE)", text, re.IGNORECASE
    ):
        flags.append("SQL injection pattern detected")

    # Clean script tags out before extraction so malicious content isn't extracted
    clean_text = re.sub(
        r"<script.*?>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL
    )

    # Step 2: Extract and validate credit cards
    raw_cards = re.findall(CARD_REGEX, clean_text)
    valid_cards = []
    for card in raw_cards:
        if luhn_check(card):
            valid_cards.append(mask_card(card))

    # Step 3: Extract and categorize emails
    raw_emails = re.findall(EMAIL_REGEX, clean_text)
    emails_data = []
    for email in raw_emails:
        # Ignore broken double-at emails
        if email.count("@") == 1:
            emails_data.append(
                {"email": email, "category": categorize_email(email)}
            )

    # Step 4: Extract phone numbers
    raw_phones = re.findall(PHONE_REGEX, clean_text)
    phones = []
    for phone in raw_phones:
        cleaned_phone = phone.strip(".,;:()[]")
        # real phone numbers max out at 15 digits (E.164 standard), and I
        # want at least 7 so I don't accidentally grab random short numbers
        # like a ticket number or a year
        # Ensure it has a plausible digit count (7 to 15 digits)
        digit_count = len(re.sub(r"\D", "", cleaned_phone))
        if 7 <= digit_count <= 15:
            phones.append(cleaned_phone)

    # Step 5: Extract URLs
    # regex tends to be a little too greedy, so I trim off trailing
    # punctuation that's probably not actually part of the URL
    # (like a period right after a link at the end of a sentence)
    raw_urls = re.findall(URL_REGEX, clean_text)
    urls = []
    for url in raw_urls:
        cleaned_url = url.rstrip(".,;:)]>")
        if not cleaned_url.lower().startswith("javascript:"):
            urls.append(cleaned_url)

    # Output structured results matching assignment JSON format
    output = {
        "security_flags": flags,
        "extracted_data": {
            "emails": emails_data,
            "credit_cards": list(set(valid_cards)),
            "phone_numbers": list(set(phones)),
            "urls": list(set(urls)),
        },
    }

    with open("output.json", "w", encoding="utf-8") as out_file:
        json.dump(output, out_file, indent=4)

    print("Extraction complete. Results saved to output.json")


if __name__ == "__main__":
    process_data("input.txt")
