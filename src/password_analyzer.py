"""
Password Strength Analyzer Module
Analyzes password strength using entropy calculation, pattern detection, and character analysis.
"""

import re
import math
import string
from typing import Dict, List, Tuple

# Common passwords list (top 100 most common)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "iloveyou", "trustno1",
    "sunshine", "master", "welcome", "shadow", "ashley", "football", "jesus",
    "michael", "ninja", "mustang", "password1", "123456a", "letmein", "monkey",
    "abc123", "admin", "login", "passw0rd", "starwars", "hello", "charlie",
    "donald", "password123", "qwerty123", "aa123456", "access", "admin123",
    "flower", "hottie", "loveme", "zaq1zaq1", "654321", "princess", "qazwsx",
    "121212", "000000", "solo", "batman", "love", "test", "killer", "hockey",
    "george", "computer", "michelle", "daniel", "tigger", "samsung", "pepper"
}

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qweasd", "1234", "4321", "0987", "7890",
    "qazwsx", "wsxedc", "rfvtgb", "yhnujm", "!@#$", "$#@!", "qwertyuiop",
    "asdfghjkl", "zxcvbnm", "1qaz2wsx", "3edc4rfv"
]

# Sequential patterns
SEQUENTIAL_PATTERNS = [
    "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl",
    "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv",
    "uvw", "vwx", "wxy", "xyz", "012", "123", "234", "345", "456", "567",
    "678", "789", "890"
]


class PasswordAnalyzer:
    """Analyzes password strength and provides detailed feedback."""

    def __init__(self, password: str):
        self.password = password
        self.length = len(password)
        self.analysis = self._analyze()

    def _analyze(self) -> Dict:
        """Perform comprehensive password analysis."""
        return {
            "length": self.length,
            "entropy": self._calculate_entropy(),
            "character_types": self._analyze_character_types(),
            "patterns": self._detect_patterns(),
            "score": 0,  # Will be calculated
            "strength": "",  # Will be determined
            "crack_time": self._estimate_crack_time(),
            "recommendations": []
        }

    def _calculate_entropy(self) -> float:
        """Calculate password entropy in bits."""
        if not self.password:
            return 0.0

        charset_size = 0

        if any(c in string.ascii_lowercase for c in self.password):
            charset_size += 26
        if any(c in string.ascii_uppercase for c in self.password):
            charset_size += 26
        if any(c in string.digits for c in self.password):
            charset_size += 10
        if any(c in string.punctuation for c in self.password):
            charset_size += 32

        if charset_size == 0:
            return 0.0

        entropy = self.length * math.log2(charset_size)
        return round(entropy, 2)

    def _analyze_character_types(self) -> Dict[str, bool]:
        """Analyze which character types are present."""
        return {
            "lowercase": any(c in string.ascii_lowercase for c in self.password),
            "uppercase": any(c in string.ascii_uppercase for c in self.password),
            "digits": any(c in string.digits for c in self.password),
            "special": any(c in string.punctuation for c in self.password)
        }

    def _detect_patterns(self) -> Dict[str, List[str]]:
        """Detect weak patterns in the password."""
        patterns = {
            "keyboard_patterns": [],
            "sequential_patterns": [],
            "repeated_chars": [],
            "common_words": [],
            "is_common_password": False
        }

        lower_password = self.password.lower()

        # Check if it's a common password
        if lower_password in COMMON_PASSWORDS:
            patterns["is_common_password"] = True

        # Check keyboard patterns
        for pattern in KEYBOARD_PATTERNS:
            if pattern in lower_password:
                patterns["keyboard_patterns"].append(pattern)

        # Check sequential patterns
        for pattern in SEQUENTIAL_PATTERNS:
            if pattern in lower_password:
                patterns["sequential_patterns"].append(pattern)
            # Check reverse
            if pattern[::-1] in lower_password:
                patterns["sequential_patterns"].append(pattern[::-1])

        # Check for repeated characters (3+ in a row)
        repeated = re.findall(r'(.)\1{2,}', self.password)
        patterns["repeated_chars"] = repeated

        return patterns

    def _estimate_crack_time(self) -> Dict[str, str]:
        """Estimate time to crack password at various speeds."""
        if not self.password:
            return {"gpu": "instant", "seconds": 0}

        entropy = self._calculate_entropy()
        combinations = 2 ** entropy

        # Assume 1 billion hashes per second (modern GPU)
        gpu_speed = 1_000_000_000
        seconds = combinations / gpu_speed

        return {
            "seconds": seconds,
            "readable": self._seconds_to_readable(seconds)
        }

    def _seconds_to_readable(self, seconds: float) -> str:
        """Convert seconds to human-readable time."""
        if seconds < 1:
            return "instant"
        elif seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.2f} years"
        elif seconds < 31536000 * 1000:
            return f"{seconds/31536000:.2f} years"
        elif seconds < 31536000 * 1000000:
            return f"{seconds/(31536000*100):.2f} centuries"
        else:
            return f"{seconds/(31536000*1000000):.2e} million years"

    def calculate_score(self) -> Tuple[int, str]:
        """Calculate overall password strength score (0-100)."""
        score = 0

        # Length scoring (max 30 points)
        if self.length >= 16:
            score += 30
        elif self.length >= 12:
            score += 25
        elif self.length >= 10:
            score += 20
        elif self.length >= 8:
            score += 15
        elif self.length >= 6:
            score += 10
        else:
            score += 5

        # Character diversity (max 25 points)
        char_types = self.analysis["character_types"]
        diversity_score = sum(char_types.values()) * 6.25
        score += diversity_score

        # Entropy scoring (max 25 points)
        entropy = self.analysis["entropy"]
        if entropy >= 80:
            score += 25
        elif entropy >= 60:
            score += 20
        elif entropy >= 45:
            score += 15
        elif entropy >= 30:
            score += 10
        else:
            score += 5

        # Pattern penalties (max -30 points)
        patterns = self.analysis["patterns"]

        if patterns["is_common_password"]:
            score -= 30

        score -= len(patterns["keyboard_patterns"]) * 5
        score -= len(patterns["sequential_patterns"]) * 3
        score -= len(patterns["repeated_chars"]) * 3

        # Ensure score is within bounds
        score = max(0, min(100, int(score)))

        # Determine strength category
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"

        self.analysis["score"] = score
        self.analysis["strength"] = strength

        return score, strength

    def get_recommendations(self) -> List[str]:
        """Generate improvement recommendations."""
        recommendations = []
        char_types = self.analysis["character_types"]
        patterns = self.analysis["patterns"]

        # Length recommendations
        if self.length < 12:
            recommendations.append("Increase password length to at least 12 characters (16+ recommended)")
        elif self.length >= 16:
            recommendations.append("✓ Excellent password length")

        # Character type recommendations
        missing_types = []
        if not char_types["lowercase"]:
            missing_types.append("lowercase letters")
        if not char_types["uppercase"]:
            missing_types.append("uppercase letters")
        if not char_types["digits"]:
            missing_types.append("digits")
        if not char_types["special"]:
            missing_types.append("special characters")

        if missing_types:
            recommendations.append(f"Add {', '.join(missing_types)} for better strength")
        elif all(char_types.values()):
            recommendations.append("✓ Uses all character types")

        # Pattern warnings
        if patterns["is_common_password"]:
            recommendations.append("⚠ This is a commonly used password - change immediately!")

        if patterns["keyboard_patterns"]:
            recommendations.append(f"⚠ Avoid keyboard patterns: {', '.join(patterns['keyboard_patterns'])}")

        if patterns["sequential_patterns"]:
            recommendations.append(f"⚠ Avoid sequential patterns: {', '.join(patterns['sequential_patterns'][:3])}")

        if patterns["repeated_chars"]:
            recommendations.append("⚠ Avoid repeating characters")

        # Entropy recommendation
        if self.analysis["entropy"] >= 60:
            recommendations.append("✓ High entropy - password is very random")
        elif self.analysis["entropy"] < 40:
            recommendations.append("Consider using a more random combination of characters")

        self.analysis["recommendations"] = recommendations
        return recommendations

    def get_full_report(self) -> Dict:
        """Generate complete analysis report."""
        self.calculate_score()
        self.get_recommendations()
        return self.analysis


def analyze_password(password: str) -> Dict:
    """Convenience function to analyze a password."""
    analyzer = PasswordAnalyzer(password)
    return analyzer.get_full_report()
