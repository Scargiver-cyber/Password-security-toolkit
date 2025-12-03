#!/usr/bin/env python3
"""
Password Security Toolkit - Streamlit GUI
A visual interface for password analysis, generation, and security assessment.
"""

import streamlit as st
from password_analyzer import PasswordAnalyzer, analyze_password
from password_generator import (
    PasswordGenerator,
    PassphraseGenerator,
    generate_pin,
    generate_password
)
from breach_detector import BreachDetector, BreachCheckError
from hash_tools import HashTools, identify_hash

# Vault imports (optional)
try:
    from password_vault import (
        PasswordVault, VaultEntry, VaultError, VaultLockedError, VaultAuthError,
        vault_exists, DEFAULT_VAULT_PATH
    )
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

# Page configuration
st.set_page_config(
    page_title="Password Security Toolkit",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .strength-very-strong { color: #00ff00; font-weight: bold; }
    .strength-strong { color: #7fff00; font-weight: bold; }
    .strength-moderate { color: #ffff00; font-weight: bold; }
    .strength-weak { color: #ff7f00; font-weight: bold; }
    .strength-very-weak { color: #ff0000; font-weight: bold; }
    .breach-warning { background-color: #ff000033; padding: 10px; border-radius: 5px; }
    .breach-safe { background-color: #00ff0033; padding: 10px; border-radius: 5px; }
    .password-display { font-family: monospace; font-size: 1.2em; background-color: #1e1e1e;
                        padding: 10px; border-radius: 5px; margin: 5px 0; }
    .metric-card { background-color: #262730; padding: 15px; border-radius: 10px; margin: 5px; }
</style>
""", unsafe_allow_html=True)


def get_strength_color(strength: str) -> str:
    """Get color class for strength level."""
    colors = {
        "Very Strong": "strength-very-strong",
        "Strong": "strength-strong",
        "Moderate": "strength-moderate",
        "Weak": "strength-weak",
        "Very Weak": "strength-very-weak"
    }
    return colors.get(strength, "")


def main():
    # Sidebar navigation
    st.sidebar.title("🔐 Password Toolkit")
    st.sidebar.markdown("---")

    # Build menu based on available features
    menu_items = [
        "🔍 Password Analyzer",
        "🎲 Password Generator",
        "📝 Passphrase Generator",
        "🔓 Breach Checker",
        "🔢 Hash Tools"
    ]

    if VAULT_AVAILABLE:
        menu_items.insert(0, "🔒 Password Vault")

    menu_items.append("📚 Security Guide")

    page = st.sidebar.radio("Select Tool", menu_items)

    st.sidebar.markdown("---")
    st.sidebar.markdown("### About")
    st.sidebar.info(
        "A comprehensive toolkit for password security. "
        "Analyze strength, generate secure passwords, "
        "check for breaches, and understand hashing."
    )

    # Main content based on selection
    if page == "🔒 Password Vault":
        password_vault_page()
    elif page == "🔍 Password Analyzer":
        password_analyzer_page()
    elif page == "🎲 Password Generator":
        password_generator_page()
    elif page == "📝 Passphrase Generator":
        passphrase_generator_page()
    elif page == "🔓 Breach Checker":
        breach_checker_page()
    elif page == "🔢 Hash Tools":
        hash_tools_page()
    elif page == "📚 Security Guide":
        security_guide_page()


def password_vault_page():
    """Password vault management page."""
    st.title("🔒 Password Vault")
    st.markdown("Securely store and manage your passwords with AES-256 encryption.")

    # Initialize session state
    if 'vault' not in st.session_state:
        st.session_state.vault = None
    if 'vault_unlocked' not in st.session_state:
        st.session_state.vault_unlocked = False

    # Check if vault exists
    vault_path_exists = vault_exists()

    # Vault status indicator
    if st.session_state.vault_unlocked:
        st.success("🔓 Vault is unlocked")
        if st.button("🔒 Lock Vault"):
            if st.session_state.vault:
                st.session_state.vault.lock()
            st.session_state.vault = None
            st.session_state.vault_unlocked = False
            st.rerun()
    else:
        st.warning("🔒 Vault is locked")

    st.markdown("---")

    # If vault doesn't exist, show setup
    if not vault_path_exists:
        st.markdown("### Create New Vault")
        st.info(
            "No vault found. Create one to securely store your passwords. "
            "Your master password encrypts all entries - **don't forget it!**"
        )

        with st.form("create_vault"):
            master_pwd = st.text_input("Master Password (min 12 chars recommended)", type="password")
            confirm_pwd = st.text_input("Confirm Master Password", type="password")

            if st.form_submit_button("🔐 Create Vault", type="primary"):
                if not master_pwd:
                    st.error("Master password is required")
                elif len(master_pwd) < 8:
                    st.error("Password must be at least 8 characters")
                elif master_pwd != confirm_pwd:
                    st.error("Passwords do not match")
                else:
                    try:
                        vault = PasswordVault()
                        vault.create(master_pwd)
                        st.session_state.vault = vault
                        st.session_state.vault_unlocked = True
                        st.success(f"✅ Vault created at {DEFAULT_VAULT_PATH}")
                        st.rerun()
                    except VaultError as e:
                        st.error(f"Error: {e}")
        return

    # Vault exists - show unlock or management interface
    if not st.session_state.vault_unlocked:
        st.markdown("### Unlock Vault")

        with st.form("unlock_vault"):
            master_pwd = st.text_input("Master Password", type="password")

            if st.form_submit_button("🔓 Unlock", type="primary"):
                try:
                    vault = PasswordVault()
                    vault.unlock(master_pwd)
                    st.session_state.vault = vault
                    st.session_state.vault_unlocked = True
                    st.rerun()
                except VaultAuthError:
                    st.error("❌ Incorrect master password")
                except VaultError as e:
                    st.error(f"Error: {e}")
        return

    # Vault is unlocked - show management interface
    vault = st.session_state.vault

    # Tabs for different operations
    tab1, tab2, tab3, tab4 = st.tabs(["📋 View Entries", "➕ Add Entry", "🔍 Search", "⚙️ Settings"])

    with tab1:
        st.markdown("### Your Stored Passwords")

        try:
            entries = vault.list_entries()
            stats = vault.get_stats()

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Entries", stats['total_entries'])
            with col2:
                st.metric("Categories", len(stats['categories']))

            if not entries:
                st.info("No entries yet. Add your first password!")
            else:
                # Filter by category
                categories = ["All"] + vault.get_categories()
                selected_cat = st.selectbox("Filter by Category", categories)

                show_passwords = st.checkbox("Show Passwords", value=False)

                filtered = entries
                if selected_cat != "All":
                    filtered = [e for e in entries if e.category == selected_cat]

                for entry in filtered:
                    with st.expander(f"🔑 {entry.name} ({entry.username})"):
                        col1, col2 = st.columns([3, 1])

                        with col1:
                            st.markdown(f"**Username:** {entry.username}")

                            if show_passwords:
                                st.markdown(f"**Password:** `{entry.password}`")
                            else:
                                st.markdown(f"**Password:** `{'•' * 12}`")

                            if entry.url:
                                st.markdown(f"**URL:** {entry.url}")
                            if entry.notes:
                                st.markdown(f"**Notes:** {entry.notes}")

                            st.caption(f"Category: {entry.category} | ID: {entry.id}")

                        with col2:
                            if st.button("📋 Copy", key=f"copy_{entry.id}"):
                                st.code(entry.password)
                                st.success("Password shown above - copy it!")

                            if st.button("🗑️ Delete", key=f"del_{entry.id}"):
                                vault.delete_entry(entry.id)
                                st.success(f"Deleted {entry.name}")
                                st.rerun()

        except VaultLockedError:
            st.error("Vault is locked")
            st.session_state.vault_unlocked = False

    with tab2:
        st.markdown("### Add New Entry")

        with st.form("add_entry"):
            name = st.text_input("Name *", placeholder="e.g., GitHub, Netflix, Bank")
            username = st.text_input("Username/Email *", placeholder="user@example.com")

            # Password options
            pwd_option = st.radio("Password", ["Generate new", "Enter manually"])

            if pwd_option == "Generate new":
                pwd_length = st.slider("Password length", 12, 32, 20)
                generated_pwd = generate_password(length=pwd_length)
                st.code(generated_pwd)
                password = generated_pwd
            else:
                password = st.text_input("Password", type="password")

            url = st.text_input("URL (optional)", placeholder="https://github.com")
            category = st.text_input("Category", value="General")
            notes = st.text_area("Notes (optional)")

            if st.form_submit_button("💾 Save Entry", type="primary"):
                if not name:
                    st.error("Name is required")
                elif not username:
                    st.error("Username is required")
                elif not password:
                    st.error("Password is required")
                else:
                    try:
                        entry = vault.add_entry(
                            name=name,
                            username=username,
                            password=password,
                            url=url if url else None,
                            category=category,
                            notes=notes if notes else None
                        )
                        st.success(f"✅ Added '{name}' to vault!")
                        st.balloons()
                    except VaultError as e:
                        st.error(f"Error: {e}")

    with tab3:
        st.markdown("### Search Entries")

        query = st.text_input("Search by name, username, or URL")

        if query:
            results = vault.search(query)

            st.markdown(f"Found **{len(results)}** results")

            for entry in results:
                with st.expander(f"🔑 {entry.name}"):
                    st.markdown(f"**Username:** {entry.username}")
                    st.markdown(f"**Category:** {entry.category}")
                    if entry.url:
                        st.markdown(f"**URL:** {entry.url}")

                    if st.button("Show Password", key=f"show_{entry.id}"):
                        st.code(entry.password)

    with tab4:
        st.markdown("### Vault Settings")

        st.markdown(f"**Vault Location:** `{DEFAULT_VAULT_PATH}`")

        stats = vault.get_stats()
        st.markdown(f"**Created:** {stats.get('created_at', 'Unknown')}")
        st.markdown(f"**Last Modified:** {stats.get('modified_at', 'Unknown')}")
        st.markdown(f"**Version:** {stats.get('version', '1.0')}")

        st.markdown("---")

        st.markdown("### Export Vault")
        st.warning("⚠️ Exporting with passwords creates an unencrypted file!")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("📤 Export (no passwords)"):
                import json
                entries = vault.export_entries(include_passwords=False)
                st.download_button(
                    "Download JSON",
                    json.dumps(entries, indent=2),
                    "vault_export.json",
                    "application/json"
                )

        with col2:
            if st.button("📤 Export (with passwords)", type="secondary"):
                import json
                entries = vault.export_entries(include_passwords=True)
                st.download_button(
                    "Download JSON (SENSITIVE!)",
                    json.dumps(entries, indent=2),
                    "vault_export_SENSITIVE.json",
                    "application/json"
                )

        st.markdown("---")
        st.markdown("### Security Info")
        st.info("""
        **Encryption:** AES-256 (Fernet)
        **Key Derivation:** PBKDF2 with 480,000 iterations
        **Storage:** Local only - never sent anywhere
        """)


def password_analyzer_page():
    """Password strength analyzer page."""
    st.title("🔍 Password Strength Analyzer")
    st.markdown("Analyze your password's strength, entropy, and security.")

    col1, col2 = st.columns([2, 1])

    with col1:
        password = st.text_input(
            "Enter password to analyze",
            type="password",
            help="Your password is analyzed locally and never sent anywhere"
        )

        show_password = st.checkbox("Show password")
        if show_password and password:
            st.code(password)

        check_breach = st.checkbox("Check against breach database", value=True)

    if password:
        # Run analysis
        analyzer = PasswordAnalyzer(password)
        report = analyzer.get_full_report()

        # Display metrics
        st.markdown("### Analysis Results")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Length", f"{report['length']} chars")
        with col2:
            st.metric("Entropy", f"{report['entropy']} bits")
        with col3:
            st.metric("Score", f"{report['score']}/100")
        with col4:
            strength_class = get_strength_color(report['strength'])
            st.markdown(f"**Strength**")
            st.markdown(f"<span class='{strength_class}'>{report['strength']}</span>",
                       unsafe_allow_html=True)

        # Character types
        st.markdown("### Character Types")
        char_cols = st.columns(4)
        char_types = report['character_types']

        with char_cols[0]:
            st.markdown(f"{'✅' if char_types['lowercase'] else '❌'} Lowercase")
        with char_cols[1]:
            st.markdown(f"{'✅' if char_types['uppercase'] else '❌'} Uppercase")
        with char_cols[2]:
            st.markdown(f"{'✅' if char_types['digits'] else '❌'} Digits")
        with char_cols[3]:
            st.markdown(f"{'✅' if char_types['special'] else '❌'} Special")

        # Crack time
        st.markdown("### Estimated Crack Time")
        st.info(f"⏱️ {report['crack_time']['readable']} (at 1 billion hashes/second)")

        # Patterns
        patterns = report['patterns']
        if any([patterns['keyboard_patterns'], patterns['sequential_patterns'],
                patterns['repeated_chars'], patterns['is_common_password']]):
            st.markdown("### ⚠️ Patterns Detected")

            if patterns['is_common_password']:
                st.error("This is a commonly used password!")
            if patterns['keyboard_patterns']:
                st.warning(f"Keyboard patterns: {', '.join(patterns['keyboard_patterns'])}")
            if patterns['sequential_patterns']:
                st.warning(f"Sequential patterns: {', '.join(patterns['sequential_patterns'][:5])}")
            if patterns['repeated_chars']:
                st.warning("Repeated characters detected")

        # Recommendations
        st.markdown("### Recommendations")
        for rec in report['recommendations']:
            if rec.startswith("✓"):
                st.success(rec)
            elif rec.startswith("⚠"):
                st.warning(rec)
            else:
                st.info(rec)

        # Breach check
        if check_breach:
            st.markdown("### Breach Database Check")
            with st.spinner("Checking against Have I Been Pwned..."):
                try:
                    detector = BreachDetector()
                    breach_report = detector.get_detailed_report(password)

                    if breach_report['is_breached']:
                        st.markdown(
                            f"""<div class='breach-warning'>
                            ⚠️ <b>WARNING:</b> Password found in {breach_report['breach_count']:,} data breaches!<br>
                            <b>Severity:</b> {breach_report['severity']}<br>
                            {breach_report['recommendation']}
                            </div>""",
                            unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            """<div class='breach-safe'>
                            ✅ Password not found in known breaches.<br>
                            <small>(Checked using k-anonymity - your password stays private)</small>
                            </div>""",
                            unsafe_allow_html=True
                        )
                except BreachCheckError as e:
                    st.error(f"Could not check breach database: {e}")


def password_generator_page():
    """Secure password generator page."""
    st.title("🎲 Secure Password Generator")
    st.markdown("Generate cryptographically secure random passwords.")

    # Options
    col1, col2 = st.columns(2)

    with col1:
        length = st.slider("Password Length", 8, 64, 16)
        count = st.slider("Number of Passwords", 1, 10, 5)

    with col2:
        st.markdown("**Character Types**")
        use_uppercase = st.checkbox("Uppercase (A-Z)", value=True)
        use_lowercase = st.checkbox("Lowercase (a-z)", value=True)
        use_digits = st.checkbox("Digits (0-9)", value=True)
        use_special = st.checkbox("Special (!@#$...)", value=True)
        exclude_ambiguous = st.checkbox("Exclude ambiguous (i,l,1,L,o,0,O)", value=False)

    if st.button("🎲 Generate Passwords", type="primary"):
        try:
            generator = PasswordGenerator(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
                exclude_ambiguous=exclude_ambiguous
            )

            passwords = generator.generate_multiple(count)

            st.markdown("### Generated Passwords")

            for i, pwd in enumerate(passwords, 1):
                analysis = analyze_password(pwd)

                col1, col2, col3 = st.columns([3, 1, 1])

                with col1:
                    st.code(pwd)
                with col2:
                    st.markdown(f"**{analysis['entropy']}** bits")
                with col3:
                    st.markdown(f"**{analysis['strength']}**")

        except ValueError as e:
            st.error(str(e))


def passphrase_generator_page():
    """Memorable passphrase generator page."""
    st.title("📝 Passphrase Generator")
    st.markdown("Generate memorable passphrases using random words.")

    col1, col2 = st.columns(2)

    with col1:
        num_words = st.slider("Number of Words", 3, 8, 4)
        count = st.slider("Number of Passphrases", 1, 10, 5)

    with col2:
        separator = st.text_input("Word Separator", value="-")
        capitalize = st.checkbox("Capitalize Words", value=True)
        include_number = st.checkbox("Include Number", value=True)

    if st.button("📝 Generate Passphrases", type="primary"):
        generator = PassphraseGenerator(
            num_words=num_words,
            separator=separator,
            capitalize=capitalize,
            include_number=include_number
        )

        passphrases = generator.generate_multiple(count)

        st.markdown("### Generated Passphrases")

        for i, phrase in enumerate(passphrases, 1):
            analysis = analyze_password(phrase)

            col1, col2, col3 = st.columns([3, 1, 1])

            with col1:
                st.code(phrase)
            with col2:
                st.markdown(f"**{analysis['entropy']}** bits")
            with col3:
                st.markdown(f"**{analysis['strength']}**")

    # PIN generator
    st.markdown("---")
    st.markdown("### PIN Generator")

    pin_col1, pin_col2 = st.columns(2)

    with pin_col1:
        pin_length = st.slider("PIN Length", 4, 8, 4)
        pin_count = st.slider("Number of PINs", 1, 10, 3)

    if st.button("🔢 Generate PINs"):
        st.markdown("### Generated PINs")
        pins = [generate_pin(pin_length) for _ in range(pin_count)]

        for pin in pins:
            st.code(pin)

        st.warning("⚠️ PINs are not suitable for high-security applications.")


def breach_checker_page():
    """Dedicated breach checker page."""
    st.title("🔓 Breach Database Checker")
    st.markdown("Check if your password has appeared in known data breaches.")

    st.info(
        "🔒 **Privacy Notice**: This tool uses k-anonymity to check your password. "
        "Only the first 5 characters of your password's hash are sent to the API. "
        "Your actual password never leaves your device."
    )

    password = st.text_input("Enter password to check", type="password")
    show = st.checkbox("Show password")

    if show and password:
        st.code(password)

    if password and st.button("🔍 Check for Breaches", type="primary"):
        with st.spinner("Checking against 800+ million breached passwords..."):
            try:
                detector = BreachDetector()
                report = detector.get_detailed_report(password)

                if report['is_breached']:
                    st.error(f"⚠️ PASSWORD COMPROMISED!")

                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Times Found", f"{report['breach_count']:,}")
                    with col2:
                        st.metric("Severity", report['severity'])

                    st.warning(report['recommendation'])

                    st.markdown("### What You Should Do")
                    st.markdown("""
                    1. **Change this password immediately** on any account using it
                    2. **Never reuse** this password anywhere
                    3. **Use a password manager** to generate unique passwords
                    4. **Enable 2FA** wherever possible
                    """)
                else:
                    st.success("✅ Good news! Password not found in any known breaches.")
                    st.markdown(
                        "While not found in breach databases, still follow security best practices: "
                        "use unique passwords, enable 2FA, and use a password manager."
                    )

            except BreachCheckError as e:
                st.error(f"Could not check breach database: {e}")


def hash_tools_page():
    """Hash identification and generation tools."""
    st.title("🔢 Hash Tools")

    tab1, tab2, tab3 = st.tabs(["Identify Hash", "Generate Hash", "Security Info"])

    with tab1:
        st.markdown("### Hash Type Identifier")
        st.markdown("Paste a hash to identify its type.")

        hash_input = st.text_input("Enter hash string")

        if hash_input and st.button("🔍 Identify Hash"):
            matches = identify_hash(hash_input)

            st.markdown(f"**Length:** {len(hash_input)} characters")

            if matches:
                st.markdown(f"**Possible Types:** {len(matches)}")

                for match in matches:
                    with st.expander(f"📌 {match['type']}", expanded=True):
                        st.markdown(match['description'])

                        if match['secure']:
                            st.success("✅ Considered secure")
                        else:
                            st.error("⚠️ Not secure for password storage")

                        if match.get('note'):
                            st.info(match['note'])
            else:
                st.warning("No matching hash types found.")

    with tab2:
        st.markdown("### Password Hasher")
        st.markdown("Hash a password with various algorithms.")

        pwd_to_hash = st.text_input("Password to hash", type="password")
        algorithm = st.selectbox("Algorithm", ["SHA256", "SHA512", "SHA1", "MD5", "ALL"])

        if pwd_to_hash and st.button("🔐 Generate Hash"):
            result = HashTools.hash_password(pwd_to_hash, algorithm)

            if algorithm == "ALL":
                for algo, hash_val in result.items():
                    st.markdown(f"**{algo}:**")
                    st.code(hash_val)
            else:
                st.markdown(f"**{algorithm}:**")
                st.code(result.get('hash', str(result)))

                if result.get('warning'):
                    st.warning(result['warning'])
                if result.get('note'):
                    st.info(result['note'])

    with tab3:
        st.markdown("### Hash Security Recommendations")

        for rec in HashTools.get_security_recommendations():
            st.markdown(f"• {rec}")


def security_guide_page():
    """Security best practices guide."""
    st.title("📚 Password Security Guide")

    st.markdown("""
    ## Creating Strong Passwords

    ### Length Matters Most
    - **Minimum 12 characters**, 16+ recommended
    - Each additional character exponentially increases security
    - A 20-character password takes millions of years to crack

    ### Character Diversity
    - ✅ Uppercase letters (A-Z)
    - ✅ Lowercase letters (a-z)
    - ✅ Numbers (0-9)
    - ✅ Special characters (!@#$%^&*)

    ### Avoid Common Patterns
    - ❌ Dictionary words (password, admin, login)
    - ❌ Personal information (birthdays, names, pets)
    - ❌ Keyboard patterns (qwerty, 123456)
    - ❌ Simple substitutions (p@ssw0rd)

    ---

    ## Passphrase Strategy

    Passphrases are memorable yet secure:

    ```
    Correct-Horse-Battery-Staple-7342
    ```

    - Easy to remember
    - High entropy (randomness)
    - Resistant to dictionary attacks

    ---

    ## Password Storage (For Developers)

    ### Recommended Algorithms
    | Algorithm | Use Case | Security |
    |-----------|----------|----------|
    | **Argon2** | Best choice | ✅ Very High |
    | **bcrypt** | Well-established | ✅ High |
    | **scrypt** | Memory-hard | ✅ High |
    | SHA-256 | Integrity only | ⚠️ Not for passwords |
    | MD5/SHA1 | Never use | ❌ Broken |

    ### Key Practices
    1. Always use unique **salts** per password
    2. Use high **iteration counts** (bcrypt cost 12+)
    3. Never store passwords in **plain text**
    4. Use **constant-time** comparison

    ---

    ## Account Security Checklist

    - [ ] Use unique password for each account
    - [ ] Enable Two-Factor Authentication (2FA)
    - [ ] Use a reputable password manager
    - [ ] Regularly check for breaches
    - [ ] Update passwords for compromised accounts
    - [ ] Never share passwords via email/chat
    """)


if __name__ == "__main__":
    main()
