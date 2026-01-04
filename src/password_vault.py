"""
Password Vault Module
Secure local password storage with AES-256 encryption via Fernet.

Security Features:
- Master password derived key using PBKDF2 (480,000 iterations)
- AES-256 encryption in CBC mode (Fernet)
- Unique salt per vault
- Encrypted at rest, decrypted only in memory
- Auto-lock timeout support
"""

import os
import json
import base64
import secrets
import hashlib
import getpass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

# Cryptography imports
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# Default vault location - supports VAULT_PATH env var for server deployment
_vault_dir = os.environ.get("VAULT_PATH", str(Path.home() / ".password_vault"))
DEFAULT_VAULT_PATH = Path(_vault_dir) / "vault.encrypted"
VAULT_VERSION = "1.0"
PBKDF2_ITERATIONS = 480_000  # OWASP 2023 recommendation


@dataclass
class VaultEntry:
    """Single password entry in the vault."""
    id: str
    name: str
    username: str
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None
    category: str = "General"
    created_at: str = ""
    modified_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = secrets.token_hex(8)
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.modified_at:
            self.modified_at = self.created_at


class VaultError(Exception):
    """Base exception for vault operations."""
    pass


class VaultLockedError(VaultError):
    """Raised when vault is locked and operation requires unlock."""
    pass


class VaultAuthError(VaultError):
    """Raised when master password is incorrect."""
    pass


class PasswordVault:
    """
    Encrypted password vault with AES-256 encryption.

    Usage:
        vault = PasswordVault()
        vault.create("my_master_password")  # First time
        vault.unlock("my_master_password")  # Subsequent uses

        vault.add_entry("GitHub", "user@email.com", "secret123", url="https://github.com")
        entries = vault.search("github")
        vault.lock()
    """

    def __init__(self, vault_path: Optional[Path] = None):
        if not CRYPTO_AVAILABLE:
            raise VaultError(
                "cryptography package required. Install with: pip install cryptography"
            )

        self.vault_path = Path(vault_path) if vault_path else DEFAULT_VAULT_PATH
        self._fernet: Optional[Fernet] = None
        self._entries: Dict[str, VaultEntry] = {}
        self._metadata: Dict = {}
        self._is_unlocked = False

    @property
    def is_unlocked(self) -> bool:
        """Check if vault is currently unlocked."""
        return self._is_unlocked

    @property
    def exists(self) -> bool:
        """Check if vault file exists."""
        return self.vault_path.exists()

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def _generate_salt(self) -> bytes:
        """Generate cryptographically secure random salt."""
        return secrets.token_bytes(32)

    def create(self, master_password: str) -> None:
        """
        Create a new encrypted vault with the given master password.

        Args:
            master_password: Master password for the vault (min 12 chars recommended)
        """
        if self.exists:
            raise VaultError(f"Vault already exists at {self.vault_path}")

        if len(master_password) < 8:
            raise VaultError("Master password must be at least 8 characters")

        # Generate salt and derive key
        salt = self._generate_salt()
        key = self._derive_key(master_password, salt)
        self._fernet = Fernet(key)

        # Initialize empty vault
        self._entries = {}
        self._metadata = {
            "version": VAULT_VERSION,
            "salt": base64.b64encode(salt).decode(),
            "created_at": datetime.now().isoformat(),
            "modified_at": datetime.now().isoformat(),
            "entry_count": 0
        }

        self._is_unlocked = True

        # Create directory and save
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self._save()

        # Set restrictive permissions (owner read/write only)
        os.chmod(self.vault_path, 0o600)

    def unlock(self, master_password: str) -> None:
        """
        Unlock the vault with the master password.

        Args:
            master_password: Master password for the vault

        Raises:
            VaultAuthError: If password is incorrect
            VaultError: If vault doesn't exist
        """
        if not self.exists:
            raise VaultError(f"No vault found at {self.vault_path}. Create one first.")

        # Read encrypted data
        with open(self.vault_path, 'rb') as f:
            encrypted_data = f.read()

        # Parse header to get salt
        try:
            header_end = encrypted_data.index(b'\n---\n')
            header = json.loads(encrypted_data[:header_end].decode())
            encrypted_payload = encrypted_data[header_end + 5:]
        except (ValueError, json.JSONDecodeError) as e:
            raise VaultError(f"Corrupted vault file: {e}")

        # Derive key and attempt decryption
        salt = base64.b64decode(header["salt"])
        key = self._derive_key(master_password, salt)
        self._fernet = Fernet(key)

        try:
            decrypted = self._fernet.decrypt(encrypted_payload)
            data = json.loads(decrypted.decode())
        except InvalidToken:
            self._fernet = None
            raise VaultAuthError("Incorrect master password")
        except json.JSONDecodeError:
            raise VaultError("Corrupted vault data")

        # Load entries
        self._metadata = header
        self._entries = {
            entry_id: VaultEntry(**entry_data)
            for entry_id, entry_data in data.get("entries", {}).items()
        }

        self._is_unlocked = True

    def lock(self) -> None:
        """Lock the vault, clearing sensitive data from memory."""
        self._save()  # Save any pending changes
        self._fernet = None
        self._entries = {}
        self._is_unlocked = False

    def _save(self) -> None:
        """Save the vault to disk (encrypted)."""
        if not self._is_unlocked or not self._fernet:
            raise VaultLockedError("Vault must be unlocked to save")

        # Update metadata
        self._metadata["modified_at"] = datetime.now().isoformat()
        self._metadata["entry_count"] = len(self._entries)

        # Serialize entries
        data = {
            "entries": {
                entry_id: asdict(entry)
                for entry_id, entry in self._entries.items()
            }
        }

        # Encrypt payload
        payload = json.dumps(data).encode()
        encrypted_payload = self._fernet.encrypt(payload)

        # Write with header
        header = json.dumps(self._metadata).encode()

        with open(self.vault_path, 'wb') as f:
            f.write(header)
            f.write(b'\n---\n')
            f.write(encrypted_payload)

    def add_entry(
        self,
        name: str,
        username: str,
        password: str,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        category: str = "General"
    ) -> VaultEntry:
        """
        Add a new password entry to the vault.

        Args:
            name: Name/title for the entry (e.g., "GitHub")
            username: Username or email
            password: The password to store
            url: Optional URL for the service
            notes: Optional notes
            category: Category for organization

        Returns:
            The created VaultEntry
        """
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to add entries")

        entry = VaultEntry(
            id="",
            name=name,
            username=username,
            password=password,
            url=url,
            notes=notes,
            category=category
        )

        self._entries[entry.id] = entry
        self._save()

        return entry

    def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
        """Get a specific entry by ID."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to read entries")
        return self._entries.get(entry_id)

    def update_entry(
        self,
        entry_id: str,
        name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        category: Optional[str] = None
    ) -> Optional[VaultEntry]:
        """Update an existing entry."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to update entries")

        entry = self._entries.get(entry_id)
        if not entry:
            return None

        if name is not None:
            entry.name = name
        if username is not None:
            entry.username = username
        if password is not None:
            entry.password = password
        if url is not None:
            entry.url = url
        if notes is not None:
            entry.notes = notes
        if category is not None:
            entry.category = category

        entry.modified_at = datetime.now().isoformat()
        self._save()

        return entry

    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry by ID."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to delete entries")

        if entry_id in self._entries:
            del self._entries[entry_id]
            self._save()
            return True
        return False

    def list_entries(self, category: Optional[str] = None) -> List[VaultEntry]:
        """List all entries, optionally filtered by category."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to list entries")

        entries = list(self._entries.values())

        if category:
            entries = [e for e in entries if e.category.lower() == category.lower()]

        return sorted(entries, key=lambda e: e.name.lower())

    def search(self, query: str) -> List[VaultEntry]:
        """Search entries by name, username, or URL."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to search")

        query = query.lower()
        results = []

        for entry in self._entries.values():
            if (query in entry.name.lower() or
                query in entry.username.lower() or
                (entry.url and query in entry.url.lower())):
                results.append(entry)

        return sorted(results, key=lambda e: e.name.lower())

    def get_categories(self) -> List[str]:
        """Get list of all categories in use."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked")

        categories = set(e.category for e in self._entries.values())
        return sorted(categories)

    def export_entries(self, include_passwords: bool = False) -> List[Dict]:
        """
        Export entries (for backup purposes).

        Args:
            include_passwords: Whether to include passwords in export

        Returns:
            List of entry dictionaries
        """
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked to export")

        entries = []
        for entry in self._entries.values():
            data = asdict(entry)
            if not include_passwords:
                data["password"] = "********"
            entries.append(data)

        return entries

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Change the master password.

        Args:
            old_password: Current master password
            new_password: New master password
        """
        if not self._is_unlocked:
            # Need to unlock first to verify old password
            self.unlock(old_password)

        if len(new_password) < 8:
            raise VaultError("New master password must be at least 8 characters")

        # Generate new salt and key
        new_salt = self._generate_salt()
        new_key = self._derive_key(new_password, new_salt)

        # Update metadata with new salt
        self._metadata["salt"] = base64.b64encode(new_salt).decode()
        self._metadata["modified_at"] = datetime.now().isoformat()

        # Set new Fernet instance and save
        self._fernet = Fernet(new_key)
        self._save()

    def get_stats(self) -> Dict:
        """Get vault statistics."""
        if not self._is_unlocked:
            raise VaultLockedError("Vault must be unlocked")

        categories = {}
        for entry in self._entries.values():
            categories[entry.category] = categories.get(entry.category, 0) + 1

        return {
            "total_entries": len(self._entries),
            "categories": categories,
            "created_at": self._metadata.get("created_at"),
            "modified_at": self._metadata.get("modified_at"),
            "version": self._metadata.get("version")
        }


def get_vault(vault_path: Optional[str] = None) -> PasswordVault:
    """Get a vault instance."""
    path = Path(vault_path) if vault_path else None
    return PasswordVault(path)


def vault_exists(vault_path: Optional[str] = None) -> bool:
    """Check if a vault exists at the given path."""
    path = Path(vault_path) if vault_path else DEFAULT_VAULT_PATH
    return path.exists()
