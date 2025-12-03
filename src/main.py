#!/usr/bin/env python3
"""
Password Security Toolkit - CLI Interface
A comprehensive command-line toolkit for password analysis, generation, and security assessment.
"""

import argparse
import sys
import getpass
from typing import Optional

from password_analyzer import PasswordAnalyzer, analyze_password
from password_generator import (
    PasswordGenerator,
    PassphraseGenerator,
    generate_password,
    generate_passphrase,
    generate_pin
)
from breach_detector import BreachDetector, BreachCheckError
from hash_tools import HashTools, identify_hash, hash_password

# Vault imports (optional - requires cryptography package)
try:
    from password_vault import (
        PasswordVault, VaultEntry, VaultError, VaultLockedError, VaultAuthError,
        vault_exists, DEFAULT_VAULT_PATH
    )
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(title.center(70))
    print("=" * 70)


def print_section(title: str):
    """Print a section divider."""
    print("\n" + "-" * 70)
    print(title)
    print("-" * 70)


def cmd_analyze(args):
    """Analyze password strength."""
    password = args.password

    print_header("PASSWORD ANALYSIS REPORT")

    # Run analysis
    analyzer = PasswordAnalyzer(password)
    report = analyzer.get_full_report()

    # Basic info
    print(f"\nPassword Length: {report['length']} characters")
    print(f"Entropy: {report['entropy']} bits")
    print(f"Strength: {report['strength']} (Score: {report['score']}/100)")

    # Character types
    print("\nCharacter Types:")
    char_types = report['character_types']
    print(f"  Lowercase: {'✓' if char_types['lowercase'] else '✗'}")
    print(f"  Uppercase: {'✓' if char_types['uppercase'] else '✗'}")
    print(f"  Digits: {'✓' if char_types['digits'] else '✗'}")
    print(f"  Special: {'✓' if char_types['special'] else '✗'}")

    # Crack time
    print(f"\nEstimated Crack Time: {report['crack_time']['readable']}")
    print("  (Using modern GPU at 1 billion hashes/second)")

    # Patterns detected
    patterns = report['patterns']
    if any([patterns['keyboard_patterns'], patterns['sequential_patterns'],
            patterns['repeated_chars'], patterns['is_common_password']]):
        print("\nPatterns Detected:")
        if patterns['is_common_password']:
            print("  ⚠ This is a commonly used password!")
        if patterns['keyboard_patterns']:
            print(f"  ⚠ Keyboard patterns: {', '.join(patterns['keyboard_patterns'])}")
        if patterns['sequential_patterns']:
            print(f"  ⚠ Sequential patterns: {', '.join(patterns['sequential_patterns'][:5])}")
        if patterns['repeated_chars']:
            print(f"  ⚠ Repeated characters detected")

    # Recommendations
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  {rec}")

    # Breach check
    if args.check_breach:
        print_section("BREACH DATABASE CHECK")
        try:
            detector = BreachDetector()
            breach_report = detector.get_detailed_report(password)

            if breach_report['is_breached']:
                print(f"\n⚠ WARNING: Password found in {breach_report['breach_count']:,} data breaches!")
                print(f"  Severity: {breach_report['severity']}")
                print(f"  {breach_report['recommendation']}")
            else:
                print("\n✓ Good news! Password not found in known breaches.")
                print("  (Checked against Have I Been Pwned database)")

        except BreachCheckError as e:
            print(f"\n⚠ Could not check breach database: {e}")

    print("\n" + "=" * 70)


def cmd_generate(args):
    """Generate secure passwords."""
    print_header("SECURE PASSWORD GENERATOR")

    generator = PasswordGenerator(
        length=args.length,
        use_uppercase=not args.no_uppercase,
        use_lowercase=not args.no_lowercase,
        use_digits=not args.no_digits,
        use_special=not args.no_special,
        exclude_ambiguous=args.exclude_ambiguous
    )

    print(f"\nGenerating {args.count} password(s) of length {args.length}:\n")

    for i, password in enumerate(generator.generate_multiple(args.count), 1):
        # Analyze each password
        analysis = analyze_password(password)
        print(f"  {i}. {password}")
        print(f"     Entropy: {analysis['entropy']} bits | "
              f"Strength: {analysis['strength']}")
        print()

    print("=" * 70)


def cmd_passphrase(args):
    """Generate memorable passphrases."""
    print_header("PASSPHRASE GENERATOR")

    generator = PassphraseGenerator(
        num_words=args.words,
        separator=args.separator,
        capitalize=not args.no_capitalize,
        include_number=not args.no_number
    )

    print(f"\nGenerating {args.count} passphrase(s) with {args.words} words:\n")

    for i, passphrase in enumerate(generator.generate_multiple(args.count), 1):
        # Analyze each passphrase
        analysis = analyze_password(passphrase)
        print(f"  {i}. {passphrase}")
        print(f"     Entropy: {analysis['entropy']} bits | "
              f"Strength: {analysis['strength']}")
        print()

    print("=" * 70)


def cmd_identify(args):
    """Identify hash type."""
    print_header("HASH IDENTIFICATION")

    hash_string = args.hash_value
    print(f"\nHash: {hash_string}")
    print(f"Length: {len(hash_string)} characters")

    matches = identify_hash(hash_string)

    if matches:
        print(f"\nPossible types: {len(matches)}")
        for match in matches:
            print(f"\n  • {match['type']}")
            print(f"    {match['description']}")
            if match.get('note'):
                print(f"    Note: {match['note']}")
            security = "✓ Secure" if match['secure'] else "⚠ Not secure"
            print(f"    Security: {security}")
    else:
        print("\n  No matching hash types found.")
        print("  The string may not be a standard hash format.")

    print("\n" + "=" * 70)


def cmd_hash(args):
    """Hash a password."""
    print_header("PASSWORD HASHING")

    password = args.password
    algorithm = args.algorithm.upper()

    print(f"\nPassword: {'*' * len(password)} ({len(password)} chars)")

    result = hash_password(password, algorithm)

    if algorithm == "ALL":
        print("\nHashes:")
        for algo, hash_val in result.items():
            print(f"\n  {algo}:")
            print(f"    {hash_val}")
    else:
        print(f"\nAlgorithm: {result.get('algorithm', algorithm)}")
        print(f"Hash: {result.get('hash', result)}")

        if result.get('warning'):
            print(f"\n⚠ Warning: {result['warning']}")
        if result.get('note'):
            print(f"\nNote: {result['note']}")

    # Security recommendations
    print_section("SECURITY RECOMMENDATIONS")
    for rec in HashTools.get_security_recommendations()[:4]:
        print(f"  • {rec}")

    print("\n" + "=" * 70)


def cmd_pin(args):
    """Generate PIN codes."""
    print_header("PIN CODE GENERATOR")

    print(f"\nGenerating {args.count} PIN(s) of length {args.length}:\n")

    for i in range(args.count):
        pin = generate_pin(args.length)
        print(f"  {i + 1}. {pin}")

    print("\n⚠ Note: PINs are not suitable for high-security applications.")
    print("  Use strong passwords or passphrases when possible.")
    print("\n" + "=" * 70)


# ============================================================================
# VAULT COMMANDS
# ============================================================================

def cmd_vault_init(args):
    """Initialize a new password vault."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required. Install with: pip install cryptography")
        sys.exit(1)

    print_header("PASSWORD VAULT SETUP")

    if vault_exists():
        print(f"\n⚠ Vault already exists at {DEFAULT_VAULT_PATH}")
        print("  Use 'vault list' to view entries or 'vault add' to add new ones.")
        return

    print("\nCreating a new encrypted password vault...")
    print("Your master password encrypts all stored passwords.")
    print("⚠ If you forget it, your passwords CANNOT be recovered!\n")

    master_password = getpass.getpass("Enter master password (min 12 chars recommended): ")
    confirm = getpass.getpass("Confirm master password: ")

    if master_password != confirm:
        print("\n❌ Passwords do not match!")
        sys.exit(1)

    try:
        vault = PasswordVault()
        vault.create(master_password)
        print(f"\n✅ Vault created successfully at {DEFAULT_VAULT_PATH}")
        print("  Your passwords are encrypted with AES-256.")
        print("\nNext steps:")
        print("  • Add entries: vault add")
        print("  • List entries: vault list")
        print("  • Search: vault search <query>")
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


def cmd_vault_add(args):
    """Add a new entry to the vault."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required.")
        sys.exit(1)

    print_header("ADD VAULT ENTRY")

    if not vault_exists():
        print("\n❌ No vault found. Create one first with: vault init")
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")

    try:
        vault = PasswordVault()
        vault.unlock(master_password)

        # Get entry details
        print("\nEnter entry details:\n")
        name = input("  Name (e.g., GitHub): ").strip()
        if not name:
            print("❌ Name is required")
            sys.exit(1)

        username = input("  Username/Email: ").strip()

        # Password - generate or enter manually
        gen_choice = input("  Generate password? [Y/n]: ").strip().lower()
        if gen_choice != 'n':
            length = input("  Password length [20]: ").strip()
            length = int(length) if length else 20
            password = generate_password(length=length)
            print(f"  Generated: {password}")
        else:
            password = getpass.getpass("  Password: ")

        url = input("  URL (optional): ").strip() or None
        category = input("  Category [General]: ").strip() or "General"
        notes = input("  Notes (optional): ").strip() or None

        # Add entry
        entry = vault.add_entry(
            name=name,
            username=username,
            password=password,
            url=url,
            category=category,
            notes=notes
        )

        vault.lock()

        print(f"\n✅ Entry '{name}' added successfully!")
        print(f"   ID: {entry.id}")

    except VaultAuthError:
        print("\n❌ Incorrect master password!")
        sys.exit(1)
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


def cmd_vault_list(args):
    """List all entries in the vault."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required.")
        sys.exit(1)

    print_header("VAULT ENTRIES")

    if not vault_exists():
        print("\n❌ No vault found. Create one first with: vault init")
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")

    try:
        vault = PasswordVault()
        vault.unlock(master_password)

        entries = vault.list_entries(category=args.category)
        stats = vault.get_stats()

        print(f"\nTotal entries: {stats['total_entries']}")
        print(f"Categories: {', '.join(stats['categories'].keys())}\n")

        if not entries:
            print("  No entries found.")
        else:
            # Group by category
            current_category = None
            for entry in entries:
                if entry.category != current_category:
                    current_category = entry.category
                    print(f"\n  [{current_category}]")

                print(f"    • {entry.name}")
                print(f"      User: {entry.username}")
                if args.show_passwords:
                    print(f"      Pass: {entry.password}")
                else:
                    print(f"      Pass: {'*' * 12}")
                if entry.url:
                    print(f"      URL:  {entry.url}")
                print(f"      ID:   {entry.id}")

        vault.lock()

    except VaultAuthError:
        print("\n❌ Incorrect master password!")
        sys.exit(1)
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

    print("\n" + "=" * 70)


def cmd_vault_get(args):
    """Get a specific entry and copy password."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required.")
        sys.exit(1)

    print_header("GET VAULT ENTRY")

    if not vault_exists():
        print("\n❌ No vault found.")
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")

    try:
        vault = PasswordVault()
        vault.unlock(master_password)

        # Search by name or ID
        query = args.name_or_id
        results = vault.search(query)

        # Also check by exact ID
        entry_by_id = vault.get_entry(query)
        if entry_by_id and entry_by_id not in results:
            results.insert(0, entry_by_id)

        if not results:
            print(f"\n❌ No entry found for '{query}'")
            vault.lock()
            sys.exit(1)

        if len(results) == 1:
            entry = results[0]
        else:
            print(f"\nMultiple matches found:")
            for i, e in enumerate(results, 1):
                print(f"  {i}. {e.name} ({e.username})")
            choice = input("\nSelect entry number: ").strip()
            entry = results[int(choice) - 1]

        print(f"\n  Name:     {entry.name}")
        print(f"  Username: {entry.username}")
        print(f"  Password: {entry.password}")
        if entry.url:
            print(f"  URL:      {entry.url}")
        if entry.notes:
            print(f"  Notes:    {entry.notes}")

        # Try to copy to clipboard
        try:
            import subprocess
            subprocess.run(['pbcopy'], input=entry.password.encode(), check=True)
            print("\n✅ Password copied to clipboard!")
        except:
            pass  # Clipboard copy is optional

        vault.lock()

    except VaultAuthError:
        print("\n❌ Incorrect master password!")
        sys.exit(1)
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

    print("\n" + "=" * 70)


def cmd_vault_search(args):
    """Search vault entries."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required.")
        sys.exit(1)

    print_header("VAULT SEARCH")

    if not vault_exists():
        print("\n❌ No vault found.")
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")

    try:
        vault = PasswordVault()
        vault.unlock(master_password)

        results = vault.search(args.query)

        print(f"\nSearch results for '{args.query}': {len(results)} found\n")

        for entry in results:
            print(f"  • {entry.name} [{entry.category}]")
            print(f"    User: {entry.username}")
            if args.show_passwords:
                print(f"    Pass: {entry.password}")
            if entry.url:
                print(f"    URL:  {entry.url}")
            print(f"    ID:   {entry.id}")
            print()

        vault.lock()

    except VaultAuthError:
        print("\n❌ Incorrect master password!")
        sys.exit(1)
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

    print("=" * 70)


def cmd_vault_delete(args):
    """Delete a vault entry."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required.")
        sys.exit(1)

    print_header("DELETE VAULT ENTRY")

    if not vault_exists():
        print("\n❌ No vault found.")
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")

    try:
        vault = PasswordVault()
        vault.unlock(master_password)

        entry = vault.get_entry(args.entry_id)
        if not entry:
            # Try searching by name
            results = vault.search(args.entry_id)
            if results:
                entry = results[0]

        if not entry:
            print(f"\n❌ Entry not found: {args.entry_id}")
            vault.lock()
            sys.exit(1)

        print(f"\n  Entry: {entry.name}")
        print(f"  User:  {entry.username}")
        print(f"  ID:    {entry.id}")

        confirm = input("\n  Delete this entry? [y/N]: ").strip().lower()
        if confirm == 'y':
            vault.delete_entry(entry.id)
            print("\n✅ Entry deleted.")
        else:
            print("\n  Cancelled.")

        vault.lock()

    except VaultAuthError:
        print("\n❌ Incorrect master password!")
        sys.exit(1)
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

    print("\n" + "=" * 70)


def cmd_vault_export(args):
    """Export vault entries to JSON."""
    if not VAULT_AVAILABLE:
        print("Error: cryptography package required.")
        sys.exit(1)

    print_header("EXPORT VAULT")

    if not vault_exists():
        print("\n❌ No vault found.")
        sys.exit(1)

    master_password = getpass.getpass("Master password: ")

    try:
        import json

        vault = PasswordVault()
        vault.unlock(master_password)

        entries = vault.export_entries(include_passwords=args.include_passwords)

        output_file = args.output or "vault_export.json"

        with open(output_file, 'w') as f:
            json.dump(entries, f, indent=2)

        vault.lock()

        print(f"\n✅ Exported {len(entries)} entries to {output_file}")

        if args.include_passwords:
            print("\n⚠ WARNING: Export contains plaintext passwords!")
            print("  Delete or secure this file after use.")

    except VaultAuthError:
        print("\n❌ Incorrect master password!")
        sys.exit(1)
    except VaultError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

    print("\n" + "=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Password Security Toolkit - Analyze, generate, and secure passwords",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze "MyP@ssw0rd!" --check-breach
  %(prog)s generate --length 20 --count 5
  %(prog)s passphrase --words 5 --count 3
  %(prog)s identify 5f4dcc3b5aa765d61d8327deb882cf99
  %(prog)s hash "MyPassword" --algorithm SHA256
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze password strength")
    analyze_parser.add_argument("password", help="Password to analyze")
    analyze_parser.add_argument("-b", "--check-breach", action="store_true",
                                help="Check password against breach database")
    analyze_parser.set_defaults(func=cmd_analyze)

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate secure passwords")
    gen_parser.add_argument("-l", "--length", type=int, default=16,
                            help="Password length (default: 16)")
    gen_parser.add_argument("-c", "--count", type=int, default=1,
                            help="Number of passwords (default: 1)")
    gen_parser.add_argument("--no-uppercase", action="store_true",
                            help="Exclude uppercase letters")
    gen_parser.add_argument("--no-lowercase", action="store_true",
                            help="Exclude lowercase letters")
    gen_parser.add_argument("--no-digits", action="store_true",
                            help="Exclude digits")
    gen_parser.add_argument("--no-special", action="store_true",
                            help="Exclude special characters")
    gen_parser.add_argument("--exclude-ambiguous", action="store_true",
                            help="Exclude ambiguous characters (i,l,1,L,o,0,O)")
    gen_parser.set_defaults(func=cmd_generate)

    # Passphrase command
    phrase_parser = subparsers.add_parser("passphrase", help="Generate memorable passphrases")
    phrase_parser.add_argument("-w", "--words", type=int, default=4,
                               help="Number of words (default: 4)")
    phrase_parser.add_argument("-c", "--count", type=int, default=1,
                               help="Number of passphrases (default: 1)")
    phrase_parser.add_argument("-s", "--separator", default="-",
                               help="Word separator (default: -)")
    phrase_parser.add_argument("--no-capitalize", action="store_true",
                               help="Do not capitalize words")
    phrase_parser.add_argument("--no-number", action="store_true",
                               help="Do not add number at end")
    phrase_parser.set_defaults(func=cmd_passphrase)

    # Identify command
    id_parser = subparsers.add_parser("identify", help="Identify hash type")
    id_parser.add_argument("hash_value", help="Hash string to identify")
    id_parser.set_defaults(func=cmd_identify)

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Hash a password")
    hash_parser.add_argument("password", help="Password to hash")
    hash_parser.add_argument("-a", "--algorithm", default="SHA256",
                             choices=["MD5", "SHA1", "SHA256", "SHA512", "ALL"],
                             help="Hash algorithm (default: SHA256)")
    hash_parser.set_defaults(func=cmd_hash)

    # PIN command
    pin_parser = subparsers.add_parser("pin", help="Generate PIN codes")
    pin_parser.add_argument("-l", "--length", type=int, default=4,
                            help="PIN length (default: 4)")
    pin_parser.add_argument("-c", "--count", type=int, default=1,
                            help="Number of PINs (default: 1)")
    pin_parser.set_defaults(func=cmd_pin)

    # ========================================================================
    # VAULT COMMANDS
    # ========================================================================

    # Vault init
    vault_init_parser = subparsers.add_parser("vault-init", help="Create a new encrypted vault")
    vault_init_parser.set_defaults(func=cmd_vault_init)

    # Vault add
    vault_add_parser = subparsers.add_parser("vault-add", help="Add entry to vault")
    vault_add_parser.set_defaults(func=cmd_vault_add)

    # Vault list
    vault_list_parser = subparsers.add_parser("vault-list", help="List vault entries")
    vault_list_parser.add_argument("-c", "--category", help="Filter by category")
    vault_list_parser.add_argument("-p", "--show-passwords", action="store_true",
                                   help="Show passwords in output")
    vault_list_parser.set_defaults(func=cmd_vault_list)

    # Vault get
    vault_get_parser = subparsers.add_parser("vault-get", help="Get entry and copy password")
    vault_get_parser.add_argument("name_or_id", help="Entry name or ID")
    vault_get_parser.set_defaults(func=cmd_vault_get)

    # Vault search
    vault_search_parser = subparsers.add_parser("vault-search", help="Search vault entries")
    vault_search_parser.add_argument("query", help="Search query")
    vault_search_parser.add_argument("-p", "--show-passwords", action="store_true",
                                     help="Show passwords in results")
    vault_search_parser.set_defaults(func=cmd_vault_search)

    # Vault delete
    vault_delete_parser = subparsers.add_parser("vault-delete", help="Delete vault entry")
    vault_delete_parser.add_argument("entry_id", help="Entry ID or name to delete")
    vault_delete_parser.set_defaults(func=cmd_vault_delete)

    # Vault export
    vault_export_parser = subparsers.add_parser("vault-export", help="Export vault to JSON")
    vault_export_parser.add_argument("-o", "--output", help="Output file path")
    vault_export_parser.add_argument("-p", "--include-passwords", action="store_true",
                                     help="Include passwords in export (CAUTION!)")
    vault_export_parser.set_defaults(func=cmd_vault_export)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
