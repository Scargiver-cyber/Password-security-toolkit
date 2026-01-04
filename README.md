# Password Security Toolkit

A comprehensive command-line toolkit for password analysis, generation, security assessment, and **encrypted local password storage**.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

### 1. Password Vault
- **AES-256 Encryption**: Military-grade encryption via Fernet
- **PBKDF2 Key Derivation**: 480,000 iterations (OWASP 2023 recommendation)
- **Local Storage**: Passwords never leave your machine
- **Master Password Protected**: Single password unlocks all entries
- **Category Organization**: Group passwords by type
- **Search & Export**: Find entries quickly, export for backup
- **Web UI**: Streamlit-based browser interface (deployable via Docker)
- **CSV Import**: Import from Apple Passwords, Chrome, 1Password with duplicate detection
- **Bulk Breach Check**: Check all passwords against HIBP with one click
- **Stale Account Finder**: Identify unused accounts for cleanup

### 2. Password Strength Analyzer
- **Entropy Calculation**: Measures password randomness in bits
- **Character Diversity Analysis**: Checks for uppercase, lowercase, digits, special characters
- **Common Pattern Detection**: Identifies keyboard patterns, sequences, common passwords
- **Crack Time Estimation**: GPU-based estimate (1 billion hashes/second)
- **Comprehensive Scoring**: 0-100 strength score with detailed feedback

### 3. Secure Password Generator
- **Cryptographically Secure**: Uses Python's `secrets` module
- **Customizable**: Length, character types, ambiguous character exclusion
- **Passphrase Generation**: Memorable multi-word passphrases
- **PIN Generation**: Random PIN codes

### 4. Breach Detection
- **Have I Been Pwned Integration**: Check against 800+ million breached passwords
- **K-Anonymity Protection**: Only first 5 hash characters sent to API
- **Privacy Preserving**: Your actual password never leaves your machine

### 5. Hash Tools
- **Hash Identification**: Auto-detect MD5, SHA1, SHA256, SHA512, bcrypt, Argon2
- **Password Hashing**: Generate hashes with multiple algorithms
- **Security Recommendations**: Best practices for password storage

## Installation

### Prerequisites
- Python 3.9 or higher
- pip (Python package installer)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Scargiver-cyber/Password-security-toolkit.git
cd Password-security-toolkit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

All commands are run from the `src/` directory:

```bash
cd src
```

### Password Vault Commands

```bash
# Initialize a new vault (first time only)
python3 main.py vault-init

# Add a password entry (interactive)
python3 main.py vault-add

# List all entries
python3 main.py vault-list

# List with passwords visible
python3 main.py vault-list -p

# Get specific entry (copies to clipboard on macOS)
python3 main.py vault-get github

# Search entries
python3 main.py vault-search "email"

# Delete an entry
python3 main.py vault-delete <entry-id>

# Export vault to JSON
python3 main.py vault-export -o backup.json
python3 main.py vault-export -o backup.json -p  # Include passwords (CAUTION!)
```

### Password Analysis

```bash
# Analyze password strength
python3 main.py analyze "MyP@ssw0rd!"

# Analyze with breach check
python3 main.py analyze "MyP@ssw0rd!" --check-breach
```

### Password Generation

```bash
# Generate secure passwords
python3 main.py generate --length 20 --count 5

# Exclude ambiguous characters
python3 main.py generate --length 16 --exclude-ambiguous

# Generate passphrases
python3 main.py passphrase --words 5 --count 3

# Generate PINs
python3 main.py pin --length 6 --count 5
```

### Hash Tools

```bash
# Identify a hash type
python3 main.py identify "5f4dcc3b5aa765d61d8327deb882cf99"

# Hash a password
python3 main.py hash "MyPassword" --algorithm SHA256

# Hash with all algorithms
python3 main.py hash "MyPassword" --algorithm ALL
```

## Project Structure

```
Password-security-toolkit/
├── README.md
├── requirements.txt
├── venv/                      # Virtual environment (created during setup)
└── src/
    ├── main.py                # CLI interface
    ├── password_vault.py      # Encrypted vault module
    ├── password_analyzer.py   # Strength analysis
    ├── password_generator.py  # Secure generation
    ├── breach_detector.py     # HIBP integration
    ├── hash_tools.py          # Hash identification
    └── app.py                 # Streamlit GUI (optional)
```

## Web UI (Streamlit)

Run the graphical web interface:

```bash
cd src
streamlit run app.py
```

Access at `http://localhost:8501`

### Web UI Features

| Tab | Features |
|-----|----------|
| **View Entries** | List all passwords, filter by category, show/hide passwords |
| **Add Entry** | Add new passwords with optional auto-generation |
| **Search** | Find entries by name, username, or URL |
| **Import** | CSV import from Apple Passwords, Chrome, 1Password |
| **Settings** | Export, Breach Check, Stale Account Finder |

### Docker Deployment

Deploy as a container for self-hosting:

```bash
# Build and run
docker build -t password-vault .
docker run -d -p 8501:8501 -v ./data:/app/data -e VAULT_PATH=/app/data password-vault
```

Or use docker-compose:

```yaml
version: '3.8'
services:
  password-vault:
    build: .
    ports:
      - "8501:8501"
    volumes:
      - ./data:/app/data
    environment:
      - VAULT_PATH=/app/data
```

## Vault Security Details

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256 via Fernet (symmetric) |
| Key Derivation | PBKDF2-HMAC-SHA256, 480,000 iterations |
| Salt | 32-byte cryptographically random per vault |
| Storage Location | `~/.password_vault/vault.encrypted` |
| File Permissions | `0600` (owner read/write only) |

**Important**: If you forget your master password, your data cannot be recovered. Keep a secure backup of your master password.

## Shell Alias (Optional)

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
alias pwtool='cd ~/path/to/Password-security-toolkit/src && ../venv/bin/python3 main.py'
```

Then use:
```bash
pwtool vault-list
pwtool generate -l 20
```

## Security Best Practices

### Password Creation
- Use at least 16 characters
- Include all character types (upper, lower, digits, special)
- Avoid common patterns and dictionary words
- Use passphrases for memorable yet strong passwords
- Never reuse passwords across accounts

### Password Storage
- Use bcrypt, Argon2, or scrypt for hashing
- Always use unique salts
- Never store passwords in plain text
- Never use MD5 or SHA1 for passwords

## Dependencies

- `requests` - HTTP library for breach checking
- `cryptography` - AES-256 encryption for vault
- `streamlit` - Web GUI (optional)

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt
- Python `secrets` module for cryptographic randomness
- Python `cryptography` library for Fernet encryption
