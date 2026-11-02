# Smart Password Security Analyzer

A command-line tool that checks password strength, flags weak passwords and risky patterns, and suggests how to make them stronger — or generates a secure password for you.

Built by **Muhammad Mansoor** — November 2026, as a self-directed cybersecurity learning project.

## Features

- **Strength score (0–100)** with rating: Very Weak → Very Strong
- **Entropy estimate** in bits (Shannon entropy)
- **Weak-password detection** against a sample common-password list
- **Pattern detection:** predictable sequences (`abc`, `123`), keyboard patterns (`qwerty`, `1qaz`), repeated characters (`aaa`)
- **Concrete suggestions** for every weak password
- **Secure password generator** using Python's `secrets` module (cryptographically strong randomness)

## Requirements

Python 3.8+. Standard library only — no installation needed.

## Usage

Analyze a password:

```bash
python password_analyzer.py "MyP@ssw0rd123"
```

Generate a secure password (default length 16):

```bash
python password_analyzer.py --generate
python password_analyzer.py --generate --length 20
```

## Example output

```
Password : M************* (14 chars)
Strength : Fair (55/100)
Entropy  : ~52.6 bits

Issues found:
  - Contains a predictable sequence (abc, 123, ...).
  - On the common-password list — attackers try these first.

Suggestions:
  - Try a passphrase: 4+ random words + a digit + a symbol.
  - Never reuse passwords — use a password manager.
  - Enable two-factor authentication wherever possible.
```

## How it works

1. **Length** earns up to 30 points (16+ characters = full points).
2. **Character variety** earns up to 40 points (lowercase, UPPERCASE, digits, symbols).
3. **Entropy** earns up to 20 points — measures how unpredictable the password actually is.
4. **Deductions** for risky patterns: common passwords (−40), sequences (−15), keyboard patterns (−15), repeats (−10), single character type (−10).

## Limitations

This is a learning/demo project, not a production password manager. The bundled common-password list is a small sample — real deployments use large breach corpora. Passwords passed as command-line arguments may remain visible in shell history; the generator is the safer path for creating new credentials.
