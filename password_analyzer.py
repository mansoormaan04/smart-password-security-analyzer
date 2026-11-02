#!/usr/bin/env python3
"""
Smart Password Security Analyzer
================================
Analyzes password strength, flags weak passwords and risky patterns,
and suggests how to make them stronger (or generates a secure one).

Scoring (0-100):
  - Length: up to 30 pts (16+ chars = full points)
  - Character variety: up to 40 pts (lower, upper, digit, symbol)
  - Entropy estimate: up to 20 pts
  - Deductions for: common passwords, sequences, keyboard patterns,
    repeated characters, single character type.

Built by Muhammad Mansoor — November 2026
Self-directed cybersecurity learning project (demo/educational use).
Standard library only.
"""

import argparse
import math
import re
import secrets
import string
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")

# Common keyboard rows used to detect patterns like "qwerty" or "1qaz".
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def load_common_passwords():
    """Load the sample common-password list shipped with the project."""
    try:
        words = set()
        for line in COMMON_PASSWORDS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                words.add(line.lower())
        return words
    except FileNotFoundError:
        return set()


def shannon_entropy(password):
    """Total Shannon entropy of the password in bits."""
    if not password:
        return 0.0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(password)
        entropy -= p * math.log2(p)
    return entropy * len(password)


def has_sequence(password):
    """Detect ascending/descending 3-char sequences like 'abc', '321'."""
    lowered = password.lower()
    for i in range(len(lowered) - 2):
        a, b, c = ord(lowered[i]), ord(lowered[i + 1]), ord(lowered[i + 2])
        if (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
            return True
    return False


def has_keyboard_pattern(password):
    """Detect 4-char runs from keyboard rows, e.g. 'qwer', '1qaz'."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            if row[i:i + 4] in lowered:
                return True
    return False


def has_repeats(password):
    """Detect 3+ repeated characters like 'aaa' or '111'."""
    return re.search(r"(.)\1{2,}", password) is not None


def analyze(password):
    common = load_common_passwords()
    findings = []
    suggestions = []
    score = 0

    # --- Length (max 30) ---
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 8:
        score += 12
    else:
        findings.append(f"Too short ({length} chars) — use at least 12, ideally 16+.")

    # --- Character variety (max 40) ---
    categories = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password),
    ])
    score += categories * 10
    if categories < 3:
        findings.append("Use a mix of lowercase, UPPERCASE, digits and symbols.")

    # --- Entropy (max 20) ---
    entropy = shannon_entropy(password)
    if entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 12
    elif entropy >= 25:
        score += 5

    # --- Risky patterns (deductions) ---
    if password.lower() in common:
        score -= 40
        findings.append("On the common-password list — attackers try these first.")
    if has_sequence(password):
        score -= 15
        findings.append("Contains a predictable sequence (abc, 123, ...).")
    if has_keyboard_pattern(password):
        score -= 15
        findings.append("Contains a keyboard pattern (qwerty, 1qaz, ...).")
    if has_repeats(password):
        score -= 10
        findings.append("Contains repeated characters (aaa, 111, ...).")
    if re.fullmatch(r"\d+", password) or re.fullmatch(r"[a-zA-Z]+", password):
        score -= 10
        findings.append("Only one character type — easy to brute-force.")

    score = max(0, min(100, score))
    if score < 20:
        rating = "Very Weak"
    elif score < 40:
        rating = "Weak"
    elif score < 60:
        rating = "Fair"
    elif score < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    if score < 80:
        suggestions.append("Try a passphrase: 4+ random words + a digit + a symbol.")
        suggestions.append("Never reuse passwords — use a password manager.")
        suggestions.append("Enable two-factor authentication wherever possible.")

    return {
        "password_masked": password[0] + "*" * (len(password) - 1) if password else "",
        "length": length,
        "score": score,
        "rating": rating,
        "entropy_bits": round(entropy, 1),
        "findings": findings,
        "suggestions": suggestions,
    }


def generate_password(length=16):
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in string.punctuation for c in pwd)):
            return pwd


def print_report(result):
    print(f"Password : {result['password_masked']} ({result['length']} chars)")
    print(f"Strength : {result['rating']} ({result['score']}/100)")
    print(f"Entropy  : ~{result['entropy_bits']} bits")
    if result["findings"]:
        print("\nIssues found:")
        for f in result["findings"]:
            print(f"  - {f}")
    else:
        print("\nNo issues found. Good password hygiene!")
    if result["suggestions"]:
        print("\nSuggestions:")
        for s in result["suggestions"]:
            print(f"  - {s}")


def main():
    parser = argparse.ArgumentParser(description="Smart Password Security Analyzer")
    parser.add_argument("password", nargs="?", help="Password to analyze (omit with --generate)")
    parser.add_argument("--generate", action="store_true", help="Generate a secure password")
    parser.add_argument("--length", type=int, default=16, help="Generated password length (default 16)")
    args = parser.parse_args()

    if args.generate:
        pwd = generate_password(args.length)
        print(f"Generated password: {pwd}")
        print_report(analyze(pwd))
    elif args.password:
        print_report(analyze(args.password))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
