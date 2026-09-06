ALU Regex Data Extraction Project

This is Python project I made to practice regex. It reads a messy text file and pulls out useful info from it: emails, credit card numbers, phone numbers, and URLs.

What it does
Finds emails and sorts ALU ones into categories (alumni, si, official, or general).
Finds credit card numbers, checks them with Luhn's algorithm, and always masks them (e.g. **** **** **** 1234) so the full number never shows up anywhere.
Finds phone numbers in different formats and checks if the digit count looks reasonable.
Finds URLs, but only http:// and https:// ones.
Before doing any of that, it scans the text for sketchy stuff like script tags or SQL-injection-looking text, and flags those instead of treating them as normal data.
How to run it
bash
python src/main.py

No extra installs needed, just Python 3.

It'll print a quick summary in the terminal and also save a full report to output/sample-output.json.

Files
src/main.py – all the code
input/raw-text.txt – the sample messy text it reads
output/sample-output.json – gets created after you run it
