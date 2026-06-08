# Password Security Toolkit

An educational learning toolkit for hands-on password security practice. Analyze password strength, generate secure passwords, check breach databases, explore hashing algorithms, and run an encrypted local password vault — all from the command line or a browser GUI.

> **For cybersecurity students:** Every tool here teaches a real concept — entropy, k-anonymity, key derivation, and more. Run the commands, read the output, and look up any term you don't recognize.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

| Tool | What you learn |
|------|----------------|
| Password Analyzer | Entropy, crack time estimation, pattern detection |
| Password Generator | Cryptographically secure randomness (`secrets` module) |
| Breach Checker | Have I Been Pwned API, k-anonymity privacy model |
| Hash Tools | MD5 / SHA / bcrypt identification and generation |
| Password Vault | AES-256 encryption, PBKDF2 key derivation, local-only storage |
| Streamlit GUI | Optional browser interface for all of the above |

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/Scargiver-cyber/Password-security-toolkit.git
cd Password-security-toolkit

# 2. Create a virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Run your first commands (from inside src/)
cd src
python3 main.py generate -l 20
python3 main.py analyze "password123"
```

> **Windows note:** Replace `source venv/bin/activate` with `venv\Scripts\activate`.

---

## Try it in 30 seconds

These two commands work immediately after install — no setup, no config file:

```bash
cd src

# Generate a 20-character password and show its entropy + strength
python3 main.py generate -l 20

# Analyze a weak password and see exactly why it fails
python3 main.py analyze "password123"
```

Expected output for `generate -l 20`:
```
======================================================================
                      SECURE PASSWORD GENERATOR
======================================================================

Generating 1 password(s) of length 20:

  1. 5k8=Nz)jFTx#9l+kI8Q!
     Entropy: 131.09 bits | Strength: Very Strong

======================================================================
```

Expected output for `analyze "password123"`:
```
Password Length: 11 characters
Entropy: 56.87 bits
Strength: Very Weak (Score: 14/100)
...
⚠ This is a commonly used password!
```

---

## Full usage reference

All CLI commands run from inside the `src/` directory.

### Password analysis

```bash
# Analyze a password (shows entropy, score, crack time, patterns)
python3 main.py analyze "MyP@ssw0rd!"

# Analyze and also check the HIBP breach database
python3 main.py analyze "MyP@ssw0rd!" --check-breach
```

### Password generation

```bash
# Generate one 16-char password (default)
python3 main.py generate

# Generate 5 passwords of length 20
python3 main.py generate --length 20 --count 5

# Skip ambiguous characters (useful for shared credentials)
python3 main.py generate --length 16 --exclude-ambiguous

# Generate passphrases (memorable, high-entropy)
python3 main.py passphrase --words 5 --count 3

# Generate PINs
python3 main.py pin --length 6 --count 5
```

### Hash tools

```bash
# Identify an unknown hash
python3 main.py identify "5f4dcc3b5aa765d61d8327deb882cf99"

# Hash a password with SHA-256
python3 main.py hash "MyPassword" --algorithm SHA256

# Show all algorithm outputs at once
python3 main.py hash "MyPassword" --algorithm ALL
```

### Encrypted vault

```bash
# Create a new vault (first time only — choose a strong master password)
python3 main.py vault-init

# Add a password entry (interactive)
python3 main.py vault-add

# List all entries
python3 main.py vault-list

# Get a specific entry (copies to clipboard on macOS)
python3 main.py vault-get github

# Search entries
python3 main.py vault-search "email"

# Export to JSON (without passwords — safe for backup)
python3 main.py vault-export -o backup.json

# Export with passwords (keep this file secure!)
python3 main.py vault-export -o backup.json -p
```

---

## Browser GUI (Streamlit)

One command launches the full visual interface:

```bash
./launch_gui.sh
```

The script sets up the virtual environment if needed, then opens the app at `http://localhost:8501`.

Or run it manually:

```bash
cd src
streamlit run app.py
```

The GUI includes all CLI features plus CSV import from Apple Passwords / Chrome / 1Password, bulk breach checking, and stale account detection.

---

## Docker deployment

Self-host the GUI in a container. The vault file persists in `./data` on your host machine.

```bash
# Build and start
docker compose up -d

# Access at http://localhost:8501
```

Or run the image directly:

```bash
docker build -t password-vault .
docker run -d -p 8501:8501 -v ./data:/app/data -e VAULT_PATH=/app/data password-vault
```

---

## Project structure

```
Password-security-toolkit/
├── README.md
├── LICENSE
├── requirements.txt
├── Dockerfile              # Container build for the Streamlit GUI
├── docker-compose.yml      # One-command compose deployment
├── launch_gui.sh           # One-command GUI launcher (handles venv setup)
└── src/
    ├── main.py             # CLI entry point
    ├── password_vault.py   # AES-256 encrypted vault
    ├── password_analyzer.py  # Entropy + pattern analysis
    ├── password_generator.py # Cryptographic password/passphrase/PIN generation
    ├── breach_detector.py  # Have I Been Pwned integration
    ├── hash_tools.py       # Hash identification and generation
    └── app.py              # Streamlit web GUI
```

---

## Make it yours

The only file you need to edit for customization is `requirements.txt` (to add packages) or `src/password_vault.py` if you want to change the default vault location.

**Vault storage location** — the vault file defaults to `~/.password_vault/vault.encrypted`. Override it with the `VAULT_PATH` environment variable:

```bash
# Before:
python3 main.py vault-init
# Vault created at: /home/yourname/.password_vault/vault.encrypted

# After (custom path):
export VAULT_PATH=/path/to/your/vaults
python3 main.py vault-init
# Vault created at: /path/to/your/vaults/vault.encrypted
```

In Docker, set it in `docker-compose.yml`:

```yaml
environment:
  - VAULT_PATH=/app/data
```

---

## Vault security details

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256 via Fernet (symmetric) |
| Key derivation | PBKDF2-HMAC-SHA256, 480,000 iterations |
| Salt | 32-byte cryptographically random per vault |
| Storage location | `~/.password_vault/vault.encrypted` (or `$VAULT_PATH`) |
| File permissions | `0600` (owner read/write only) |

If you forget your master password, the data cannot be recovered. Keep a secure backup of the master password itself.

---

## Optional shell alias

Add to your `~/.zshrc` or `~/.bashrc` so you can type `pwtool` from anywhere:

```bash
alias pwtool='cd /path/to/Password-security-toolkit/src && ../venv/bin/python3 main.py'
```

Replace `/path/to/` with the actual clone location. Then:

```bash
pwtool generate -l 20
pwtool analyze "mypassword"
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'password_analyzer'`**
You ran `python3 main.py` from the repo root instead of `src/`. All CLI commands must run from inside `src/`:
```bash
cd src
python3 main.py generate -l 20
```

**`ModuleNotFoundError: No module named 'cryptography'` (or similar)**
The virtual environment is not activated. Run:
```bash
source venv/bin/activate      # macOS/Linux
venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

**`vault-get` doesn't copy to clipboard**
Clipboard copy (`pbcopy`) is macOS only. On Linux, install `xclip` and the code will fall back gracefully; on Windows, copy the password shown on screen manually.

**Streamlit port already in use**
Another app is using port 8501. Pick a different port:
```bash
streamlit run app.py --server.port 8502
```

**Docker: `permission denied` on `./data`**
The container runs as root by default. Create the data directory first:
```bash
mkdir -p data
docker compose up -d
```

---

## Security best practices

- Use at least 16 characters; longer is always better.
- Mix all character types (upper, lower, digits, special).
- Never reuse passwords across accounts.
- Store with bcrypt, Argon2, or scrypt — never MD5 or SHA-1.
- Enable two-factor authentication wherever possible.

---

## Dependencies

- `requests` — HTTP client for HIBP breach API
- `cryptography` — AES-256 Fernet encryption for the vault
- `streamlit` — optional browser GUI

---

## Credits

Built by [Jason Tilson](https://github.com/Scargiver-cyber) for cybersecurity education.

- [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt — breach database API
- Python `secrets` module — cryptographically secure random generation
- Python `cryptography` library — Fernet AES-256 encryption

---

## License

MIT License — see [LICENSE](LICENSE) for details.
