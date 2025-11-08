# Password Security Toolkit

A comprehensive command-line toolkit for password analysis, generation, and security assessment. This tool helps you create strong passwords, analyze password strength, check for data breaches, and understand password hashing.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

### 1. Password Strength Analyzer
- **Entropy Calculation**: Measures password randomness and unpredictability
- **Character Diversity Analysis**: Checks for uppercase, lowercase, digits, and special characters
- **Common Pattern Detection**: Identifies weak patterns like sequential characters, keyboard patterns, and common passwords
- **Crack Time Estimation**: Calculates estimated time to crack using modern GPU (1 billion hashes/second)
- **Comprehensive Scoring**: 0-100 strength score with detailed feedback

### 2. Secure Password Generator
- **Cryptographically Secure**: Uses Python's `secrets` module for true randomness
- **Customizable Length**: Generate passwords of any length
- **Character Type Control**: Include/exclude uppercase, lowercase, digits, special characters
- **Ambiguous Character Exclusion**: Option to exclude confusing characters (i, l, 1, L, o, 0, O)
- **Minimum Requirements**: Ensure minimum counts of each character type
- **Passphrase Generation**: Create memorable passphrases using random words
- **PIN Generation**: Generate random PIN codes

### 3. Breach Detection
- **Have I Been Pwned Integration**: Check passwords against 800+ million breached passwords
- **K-Anonymity Protection**: Uses k-anonymity model - only sends first 5 characters of hash
- **Privacy Preserving**: Your actual password never leaves your machine
- **Severity Rating**: Provides breach severity based on occurrence count
- **Email Breach Checking**: Check if email appears in data breaches (requires API key)

### 4. Hash Tools
- **Hash Identification**: Automatically identify hash types (MD5, SHA1, SHA256, SHA512, bcrypt, Argon2, etc.)
- **Password Hashing**: Hash passwords with various algorithms
- **Hash Comparison**: Verify passwords against hash values
- **Salt Generation**: Generate cryptographically secure random salts
- **Security Recommendations**: Provides guidance on secure hashing practices

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/password-security-toolkit.git
cd password-security-toolkit

# Install dependencies
pip install -r requirements.txt

# Make the main script executable
chmod +x src/main.py
```

### Install with pip (optional)

```bash
pip install -e .
```

## Usage

### Basic Commands

```bash
# Navigate to src directory
cd src

# Analyze a password
python3 main.py analyze "MyP@ssw0rd!" --check-breach

# Generate strong passwords
python3 main.py generate --length 20 --count 5

# Generate passphrases
python3 main.py passphrase --words 5 --count 3

# Identify a hash type
python3 main.py identify 5f4dcc3b5aa765d61d8327deb882cf99

# Hash a password
python3 main.py hash "MyPassword" --algorithm SHA256
```

### Detailed Command Reference

#### 1. Analyze Password

Analyze password strength and optionally check for breaches:

```bash
python3 main.py analyze "YourPassword" [OPTIONS]

Options:
  --check-breach, -b    Check password against breach database
```

**Example Output:**
```
======================================================================
PASSWORD ANALYSIS REPORT
======================================================================

Password Length: 15 characters
Entropy: 77.54 bits
Strength: Strong (Score: 75/100)

Character Types:
  Lowercase: ✓
  Uppercase: ✓
  Digits: ✓
  Special: ✓

Estimated Crack Time: 4.52 centuries
  (Using modern GPU at 1 billion hashes/second)

Recommendations:
  ✓ Excellent password length
  ✓ Uses all character types
  ✓ High entropy - password is very random

----------------------------------------------------------------------
BREACH DATABASE CHECK
----------------------------------------------------------------------

✓ Good news! Password not found in known breaches.
  (Checked against Have I Been Pwned database)

======================================================================
```

#### 2. Generate Passwords

Generate cryptographically secure random passwords:

```bash
python3 main.py generate [OPTIONS]

Options:
  --length, -l LENGTH           Password length (default: 16)
  --count, -c COUNT            Number of passwords (default: 1)
  --no-uppercase               Exclude uppercase letters
  --no-lowercase               Exclude lowercase letters
  --no-digits                  Exclude digits
  --no-special                 Exclude special characters
  --exclude-ambiguous          Exclude ambiguous characters (i,l,1,L,o,0,O)
```

**Examples:**
```bash
# Generate a single 16-character password
python3 main.py generate

# Generate 5 long passwords (24 characters)
python3 main.py generate --length 24 --count 5

# Generate password without special characters
python3 main.py generate --no-special

# Generate password excluding ambiguous characters
python3 main.py generate --exclude-ambiguous --length 20
```

#### 3. Generate Passphrases

Create memorable passphrases using random words:

```bash
python3 main.py passphrase [OPTIONS]

Options:
  --words, -w WORDS       Number of words (default: 4)
  --count, -c COUNT       Number of passphrases (default: 1)
  --separator, -s SEP     Word separator (default: -)
  --no-capitalize         Do not capitalize words
  --no-number            Do not add number at end
```

**Examples:**
```bash
# Generate a 4-word passphrase
python3 main.py passphrase

# Generate 3 passphrases with 5 words each
python3 main.py passphrase --words 5 --count 3

# Generate lowercase passphrase without number
python3 main.py passphrase --no-capitalize --no-number

# Use custom separator
python3 main.py passphrase --separator "_"
```

**Example Output:**
```
Correct-Horse-Battery-Staple-7342
```

#### 4. Identify Hash

Identify the type of a hash string:

```bash
python3 main.py identify "HASH_STRING"
```

**Example:**
```bash
python3 main.py identify 5f4dcc3b5aa765d61d8327deb882cf99

# Output:
# Possible types: 2
#
#   • MD5
#     MD5 (Message Digest 5) - deprecated, not secure
#
#   • NTLM
#     NTLM (Windows) - same length as MD5, context needed
```

#### 5. Hash Password

Hash a password using various algorithms:

```bash
python3 main.py hash "PASSWORD" [OPTIONS]

Options:
  --algorithm, -a ALGO    Algorithm: MD5, SHA1, SHA256, SHA512, ALL (default: SHA256)
```

**Examples:**
```bash
# Hash with SHA256
python3 main.py hash "MyPassword"

# Hash with all algorithms
python3 main.py hash "MyPassword" --algorithm ALL

# Hash with MD5 (not recommended)
python3 main.py hash "MyPassword" --algorithm MD5
```

## Docker Usage

Run the toolkit in an isolated Docker container:

### Build the Docker Image

```bash
docker build -t password-toolkit .
```

### Run Commands in Docker

```bash
# Analyze a password
docker run --rm password-toolkit analyze "MyP@ssw0rd!" --check-breach

# Generate passwords
docker run --rm password-toolkit generate --length 20 --count 5

# Interactive mode
docker run --rm -it password-toolkit /bin/bash
```

## Project Structure

```
password-security-toolkit/
├── src/
│   ├── main.py                 # CLI interface
│   ├── password_analyzer.py    # Password strength analysis
│   ├── password_generator.py   # Secure password generation
│   ├── breach_detector.py      # Breach detection via HIBP
│   └── hash_tools.py           # Hash identification and tools
├── tests/
│   └── (unit tests)
├── docs/
│   └── (additional documentation)
├── examples/
│   └── (usage examples)
├── requirements.txt            # Python dependencies
├── setup.py                    # Package setup
├── Dockerfile                  # Docker configuration
├── .gitignore                  # Git ignore rules
└── README.md                   # This file
```

## Security Best Practices

### Password Creation
1. **Use at least 16 characters** for strong passwords
2. **Include all character types**: uppercase, lowercase, digits, special characters
3. **Avoid common patterns**: sequential characters, keyboard patterns, dictionary words
4. **Use passphrases** for memorable yet strong passwords
5. **Never reuse passwords** across different accounts

### Password Storage
1. **Never store passwords in plain text**
2. **Use bcrypt, Argon2, or scrypt** for password hashing
3. **Always use unique salts** for each password
4. **Use high iteration counts** (cost factors)
5. **Never use MD5 or SHA1** for password storage

### This Tool
- Passwords analyzed for breaches are checked via k-anonymity (only 5 characters of hash sent)
- Generated passwords use `secrets` module (cryptographically secure)
- No passwords are logged or stored
- Hash comparisons are performed locally

## Examples

### Example 1: Complete Password Security Workflow

```bash
# 1. Generate a strong password
python3 main.py generate --length 20

# Output: q7#Km9@nX2$pR5*hL8^w

# 2. Analyze its strength
python3 main.py analyze "q7#Km9@nX2$pR5*hL8^w"

# 3. Check if it's been breached
python3 main.py analyze "q7#Km9@nX2$pR5*hL8^w" --check-breach
```

### Example 2: Generate Multiple Strong Passwords

```bash
# Generate 10 strong passwords for different accounts
python3 main.py generate --length 18 --count 10 --exclude-ambiguous
```

### Example 3: Create Memorable Passphrase

```bash
# Generate a passphrase that's strong but memorable
python3 main.py passphrase --words 5 --separator "-"

# Output: Thunder-Mountain-Quantum-Phoenix-8472
```

### Example 4: Check Existing Password

```bash
# Check if your current password is compromised
python3 main.py analyze "YourCurrentPassword" --check-breach
```

## API Integration: Have I Been Pwned

The breach detection feature uses the [Have I Been Pwned](https://haveibeenpwned.com/) API by Troy Hunt.

### How It Works
1. Your password is hashed locally with SHA-1
2. Only the first 5 characters of the hash are sent to HIBP API
3. HIBP returns all hashes starting with those 5 characters
4. The full hash is compared locally to find matches
5. **Your actual password never leaves your machine**

### Privacy
This implements k-anonymity, ensuring your password remains private while still checking against breach databases.

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/password-security-toolkit.git

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov

# Run tests
pytest tests/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt for the breach detection API
- Python's `secrets` module for cryptographically secure random generation
- The cybersecurity community for best practices and standards

## Disclaimer

This tool is for educational and security assessment purposes. Always follow responsible disclosure practices and obtain proper authorization before testing systems you don't own.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/password-security-toolkit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/password-security-toolkit/discussions)

## Roadmap

Future enhancements planned:
- [ ] GUI interface
- [ ] Password manager integration
- [ ] Custom wordlist support for passphrases
- [ ] Bulk password analysis from files
- [ ] Password policy compliance checking
- [ ] Multi-language support
- [ ] Web interface

---

**Made with security in mind** 🔐
