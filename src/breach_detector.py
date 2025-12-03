"""
Breach Detection Module
Check passwords against the Have I Been Pwned database using k-anonymity.
"""

import hashlib
import requests
from typing import Tuple, Optional, Dict


class BreachDetector:
    """Check passwords against breach databases using k-anonymity."""

    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Password-Security-Toolkit",
            "Add-Padding": "true"  # Adds padding to prevent response length analysis
        })

    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-1 (required by HIBP API)."""
        return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    def check_password(self, password: str) -> Tuple[bool, int]:
        """
        Check if password has been breached using k-anonymity.

        Returns:
            Tuple of (is_breached: bool, occurrence_count: int)
        """
        # Get SHA-1 hash
        sha1_hash = self._hash_password(password)

        # k-anonymity: only send first 5 characters
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            response = self.session.get(
                f"{self.HIBP_API_URL}{prefix}",
                timeout=self.timeout
            )
            response.raise_for_status()

            # Parse response - format is SUFFIX:COUNT per line
            hashes = response.text.splitlines()

            for hash_line in hashes:
                parts = hash_line.split(':')
                if len(parts) == 2:
                    hash_suffix, count = parts
                    if hash_suffix == suffix:
                        return True, int(count)

            return False, 0

        except requests.exceptions.RequestException as e:
            raise BreachCheckError(f"Failed to check breach database: {e}")

    def get_breach_severity(self, count: int) -> str:
        """Get severity rating based on breach occurrence count."""
        if count == 0:
            return "Safe"
        elif count < 10:
            return "Low"
        elif count < 100:
            return "Medium"
        elif count < 1000:
            return "High"
        elif count < 10000:
            return "Very High"
        else:
            return "Critical"

    def get_detailed_report(self, password: str) -> Dict:
        """Get detailed breach report for a password."""
        is_breached, count = self.check_password(password)

        return {
            "password_checked": True,
            "is_breached": is_breached,
            "breach_count": count,
            "severity": self.get_breach_severity(count),
            "recommendation": self._get_recommendation(is_breached, count)
        }

    def _get_recommendation(self, is_breached: bool, count: int) -> str:
        """Get recommendation based on breach status."""
        if not is_breached:
            return "Password not found in known breaches. Still recommended to use unique passwords for each account."

        if count < 100:
            return "Password found in some breaches. Consider changing it soon."
        elif count < 1000:
            return "Password appears frequently in breaches. Change immediately."
        else:
            return f"Password found {count:,} times in breaches! Change immediately and never reuse this password."


class BreachCheckError(Exception):
    """Exception raised when breach check fails."""
    pass


def check_password_breach(password: str) -> Tuple[bool, int]:
    """Convenience function to check a password against breach database."""
    detector = BreachDetector()
    return detector.check_password(password)


def is_password_breached(password: str) -> bool:
    """Simple check if password has been breached."""
    is_breached, _ = check_password_breach(password)
    return is_breached
