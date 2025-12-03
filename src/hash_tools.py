"""
Hash Tools Module
Identify hash types, hash passwords, and verify hashes.
"""

import hashlib
import secrets
import re
from typing import List, Dict, Optional, Tuple


# Hash patterns for identification
HASH_PATTERNS = {
    "MD5": {
        "pattern": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "description": "MD5 (Message Digest 5) - deprecated, not secure for passwords",
        "secure": False
    },
    "SHA1": {
        "pattern": r"^[a-fA-F0-9]{40}$",
        "length": 40,
        "description": "SHA-1 (Secure Hash Algorithm 1) - deprecated, not secure",
        "secure": False
    },
    "SHA256": {
        "pattern": r"^[a-fA-F0-9]{64}$",
        "length": 64,
        "description": "SHA-256 - secure for integrity checks, not recommended for passwords alone",
        "secure": True
    },
    "SHA512": {
        "pattern": r"^[a-fA-F0-9]{128}$",
        "length": 128,
        "description": "SHA-512 - secure for integrity checks, not recommended for passwords alone",
        "secure": True
    },
    "NTLM": {
        "pattern": r"^[a-fA-F0-9]{32}$",
        "length": 32,
        "description": "NTLM (Windows) - same length as MD5, context-dependent",
        "secure": False
    },
    "bcrypt": {
        "pattern": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
        "length": 60,
        "description": "bcrypt - recommended for password storage, includes salt",
        "secure": True
    },
    "Argon2": {
        "pattern": r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
        "length": None,  # Variable
        "description": "Argon2 - modern, highly secure password hashing",
        "secure": True
    },
    "scrypt": {
        "pattern": r"^\$scrypt\$",
        "length": None,
        "description": "scrypt - memory-hard password hashing",
        "secure": True
    },
    "MySQL5": {
        "pattern": r"^\*[A-F0-9]{40}$",
        "length": 41,
        "description": "MySQL 5.x password hash",
        "secure": False
    },
    "SHA256_Unix": {
        "pattern": r"^\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$",
        "length": None,
        "description": "SHA-256 Unix crypt format with salt",
        "secure": True
    },
    "SHA512_Unix": {
        "pattern": r"^\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}$",
        "length": None,
        "description": "SHA-512 Unix crypt format with salt",
        "secure": True
    }
}


class HashTools:
    """Tools for identifying, generating, and verifying password hashes."""

    @staticmethod
    def identify_hash(hash_string: str) -> List[Dict]:
        """
        Identify possible hash types from a hash string.

        Returns list of possible matches with descriptions.
        """
        hash_string = hash_string.strip()
        matches = []

        for hash_type, info in HASH_PATTERNS.items():
            if re.match(info["pattern"], hash_string):
                matches.append({
                    "type": hash_type,
                    "description": info["description"],
                    "secure": info["secure"],
                    "length": info["length"]
                })

        # Handle MD5/NTLM ambiguity
        if len(matches) > 1:
            md5_ntlm = [m for m in matches if m["type"] in ("MD5", "NTLM")]
            if len(md5_ntlm) == 2:
                # Add note about ambiguity
                for m in matches:
                    if m["type"] in ("MD5", "NTLM"):
                        m["note"] = "Cannot distinguish between MD5 and NTLM without context"

        return matches

    @staticmethod
    def hash_password(password: str, algorithm: str = "SHA256") -> Dict:
        """
        Hash a password with the specified algorithm.

        Supported: MD5, SHA1, SHA256, SHA512
        """
        algorithm = algorithm.upper()

        if algorithm == "MD5":
            hash_obj = hashlib.md5(password.encode())
            return {
                "algorithm": "MD5",
                "hash": hash_obj.hexdigest(),
                "warning": "MD5 is not secure for password storage!"
            }

        elif algorithm == "SHA1":
            hash_obj = hashlib.sha1(password.encode())
            return {
                "algorithm": "SHA1",
                "hash": hash_obj.hexdigest(),
                "warning": "SHA1 is not secure for password storage!"
            }

        elif algorithm == "SHA256":
            hash_obj = hashlib.sha256(password.encode())
            return {
                "algorithm": "SHA256",
                "hash": hash_obj.hexdigest(),
                "note": "For password storage, use bcrypt or Argon2 instead"
            }

        elif algorithm == "SHA512":
            hash_obj = hashlib.sha512(password.encode())
            return {
                "algorithm": "SHA512",
                "hash": hash_obj.hexdigest(),
                "note": "For password storage, use bcrypt or Argon2 instead"
            }

        elif algorithm == "ALL":
            return {
                "MD5": hashlib.md5(password.encode()).hexdigest(),
                "SHA1": hashlib.sha1(password.encode()).hexdigest(),
                "SHA256": hashlib.sha256(password.encode()).hexdigest(),
                "SHA512": hashlib.sha512(password.encode()).hexdigest()
            }

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """Generate a cryptographically secure random salt."""
        return secrets.token_hex(length // 2)

    @staticmethod
    def hash_with_salt(password: str, salt: Optional[str] = None,
                       algorithm: str = "SHA256") -> Dict:
        """Hash password with a salt."""
        if salt is None:
            salt = HashTools.generate_salt()

        salted_password = salt + password

        if algorithm.upper() == "SHA256":
            hash_obj = hashlib.sha256(salted_password.encode())
        elif algorithm.upper() == "SHA512":
            hash_obj = hashlib.sha512(salted_password.encode())
        else:
            raise ValueError(f"Unsupported algorithm for salted hash: {algorithm}")

        return {
            "algorithm": algorithm.upper(),
            "salt": salt,
            "hash": hash_obj.hexdigest(),
            "combined": f"{salt}${hash_obj.hexdigest()}"
        }

    @staticmethod
    def verify_hash(password: str, hash_value: str,
                    algorithm: str = "SHA256", salt: Optional[str] = None) -> bool:
        """Verify a password against a hash."""
        if salt:
            result = HashTools.hash_with_salt(password, salt, algorithm)
            return result["hash"] == hash_value
        else:
            result = HashTools.hash_password(password, algorithm)
            if isinstance(result, dict) and "hash" in result:
                return result["hash"].lower() == hash_value.lower()
            return False

    @staticmethod
    def get_security_recommendations() -> List[str]:
        """Get security recommendations for password hashing."""
        return [
            "Use bcrypt, Argon2, or scrypt for password storage",
            "Never use MD5 or SHA1 for passwords - they are too fast to hash",
            "Always use a unique salt for each password",
            "Use high cost factors/iterations (bcrypt: 12+, Argon2: tune to ~0.5s)",
            "Store the algorithm, salt, and hash together",
            "Never store passwords in plain text",
            "Use constant-time comparison to prevent timing attacks",
            "Consider using a pepper (server-side secret) in addition to salt"
        ]


def identify_hash(hash_string: str) -> List[Dict]:
    """Convenience function to identify a hash."""
    return HashTools.identify_hash(hash_string)


def hash_password(password: str, algorithm: str = "SHA256") -> Dict:
    """Convenience function to hash a password."""
    return HashTools.hash_password(password, algorithm)
