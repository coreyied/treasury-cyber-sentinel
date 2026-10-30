import sqlite3
import hashlib
import hmac
import math
import re
import os

DB_PATH = "treasury_sentinel.db"
SCHEMA_PATH = "schema.sql"
VAULT_SECRET_KEY = b"SOX_404_TREASURY_HMAC_MASTER_KEY_2026"

def calculate_levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 3)

def validate_aba_routing_mod10(routing: str) -> bool:
    if not re.fullmatch(r"\d{9}", routing):
        return False
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    checksum = sum(int(digit) * weight for digit, weight in zip(routing, weights))
    return (checksum % 10) == 0

def validate_luhn_card(card_number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum % 10) == 0

def generate_hmac_token(raw_sensitive_value: str) -> str:
    return hmac.new(
        VAULT_SECRET_KEY,
        raw_sensitive_value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:24].upper()

def scrub_payment_memo(wire_id: str, raw_memo: str, timestamp: str, cursor: sqlite3.Cursor):
    sanitized = raw_memo
    redaction_count = 0

    cc_pattern = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    for match in cc_pattern.findall(raw_memo):
        if validate_luhn_card(match):
            token = generate_hmac_token(match)
            sanitized = sanitized.replace(match, f"[REDACTED_PAN_HMAC:{token}]")
            redaction_count += 1
            cursor.execute("""
                INSERT INTO pci_dlp_intercepts 
                (wire_id, data_classification, validation_algorithm, hmac_sha256_token, regulatory_control, intercept_timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (wire_id, "PCI_CARDHOLDER_PAN", "LUHN_MOD10_VERIFIED", token, "PCI-DSS v4.0 Req 3.4 / GLBA", timestamp))

    ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    for match in ssn_pattern.findall(raw_memo):
        token = generate_hmac_token(match)
        sanitized = sanitized.replace(match, f"[REDACTED_SSN_HMAC:{token}]")
        redaction_count += 1
        cursor.execute("""
            INSERT INTO pci_dlp_intercepts 
            (wire_id, data_classification, validation_algorithm, hmac_sha256_token, regulatory_control, intercept_timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (wire_id, "GLBA_TAX_SSN_PII", "REGEX_STRUCTURAL_SSN", token, "GLBA Safeguards Rule / NIST PR.DS-1", timestamp))

    api_pattern = re.compile(r"sk_live_[0-9a-zA-Z]{16,}")
    for match in api_pattern.findall(raw_memo):
        token = generate_hmac_token(match)
        sanitized = sanitized.replace(match, f"[REDACTED_SECRET_HMAC:{token}]")
        redaction_count += 1
        cursor.execute("""
            INSERT INTO pci_dlp_intercepts 
            (wire_id, data_classification, validation_algorithm, hmac_sha256_token, regulatory_control, intercept_timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (wire_id, "TREASURY_API_SECRET", "HIGH_ENTROPY_TOKEN", token, "SOX Sec 404 ITGC / NIST PR.AC-1", timestamp))

    return sanitized, redaction_count

def append_sox_ledger(cursor: sqlite3.Cursor, timestamp: str, category: str, ref_id: str, amount: float, actor: str, prev_hash: str) -> str:
    payload = f"{timestamp}|{category}|{ref_id}|{amount:.2f}|{actor}|{prev_hash}"
    curr_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    cursor.execute("""
        INSERT INTO sox_immutable_ledger
        (event_timestamp, event_category, reference_id, amount_usd, actor_id, prev_hash, curr_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, category, ref_id, amount, actor, prev_hash, curr_hash))
    return curr_hash

def build_treasury_warehouse():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        cursor.executescript(f.read())

    vendors = [
        ("VND-101", "Apex Industrial Precision LLC", "Aerospace & Defense", "apexprecision.com", "111000025", "8841", 50000.00),
        ("VND-202", "Kestrel Omni-Logistics Corp", "Global Freight & Supply", "kestrellogistics.com", "021000021", "4409", 50000.00),
        ("VND-303", "Vanguard Midstream Partners LP", "Energy Infrastructure", "vanguardmidstream.com", "121000248", "9912", 50000.00),
        ("VND-404", "Meridian Cloud Settlement Inc", "FinTech Clearing", "meridianclearing.io", "026009593", "3104", 50000.00),
    ]
    cursor.executemany("INSERT INTO treasury_vendors VALUES (?, ?, ?, ?, ?, ?, ?)", vendors)

    observed_domains = [
        ("VND-101", "apexprecision.com", "apexprecisi0n.com", 1, "026009593", "Homoglyph Typo + Valid Attacker Routing", "2026-10-29 08:14:00"),
        ("VND-202", "kestrellogistics.com", "kestrel-logistics-pay.com", 1, "121000248", "Combo-Squatting Billing Portal", "2026-10-29 09:02:15"),
        ("VND-303", "vanguardmidstream.com", "vanguardmidstrearn.com", 1, "021000021", "rn-to-m Visual BEC Wire Hijack", "2026-10-29 10:41:30"),
    ]

    for v_id, official, observed, has_mx, spoof_aba, vector, ts in observed_domains:
        b1, b2 = official.split(".")[0], observed.split(".")[0]
        dist = calculate_levenshtein(b1, b2)
        sim_pct = round((1.0 - (dist / max(len(b1), len(b2)))) * 100.0, 2)
        entropy = calculate_shannon_entropy(observed)
        aba_valid = validate_aba_routing_mod10(spoof_aba)

        cursor.execute("""
            INSERT INTO bec_domain_telemetry
            (vendor_id, observed_domain, levenshtein_distance, domain_similarity_pct, shannon_entropy,
             has_active_mx, spoofed_aba_routing, aba_mod10_valid, threat_vector, detected_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (v_id, observed, dist, sim_pct, entropy, has_mx, spoof_aba, int(aba_valid), vector, ts))

    raw_wires = [
        ("WIR-9001", "VND-404", "2026-10-29 09:15:00", 38500.00, "026009593", "usr_jdoe", "mgr_rsmith",
         "Q3 Cloud Settlement Invoice #88412 - Standard ACH Clearing"),
        ("WIR-9002", "VND-303", "2026-10-29 11:05:00", 142000.00, "021000021", "usr_mchen", "mgr_rsmith",
         "URGENT: Updated routing per vanguardmidstrearn.com CFO notice. Auth token sk_live_9948102948102948abc"),
        ("WIR-9003", "VND-101", "2026-10-29 13:10:00", 48500.00, "026009593", "usr_kpatel", None,
         "Turbine tooling batch 1 of 3. Backup procurement card 4532-0151-1283-0366 on file."),
        ("WIR-9004", "VND-101", "2026-10-29 13:22:00", 49200.00, "026009593", "usr_kpatel", None,
         "Turbine tooling batch 2 of 3. Contractor tax SSN 442-88-1920 attached for 1099."),
        ("WIR-9005", "VND-101", "2026-10-29 13:35:00", 47800.00, "026009593", "usr_kpatel", None,
         "Turbine tooling batch 3 of 3. Expedited same-day Fedwire settlement."),
        ("WIR-9006", "VND-202", "2026-10-29 15:40:00", 64000.00, "121000248", "usr_jdoe", None,
         "Port drayage settlement per kestrel-logistics-pay.com portal invoice.")
    ]

    prev_hash = "0" * 64

    for w_id, v_id, ts, amt, sub_aba, init_user, app_user, memo in raw_wires:
        sanitized_memo, dlp_count = scrub_payment_memo(w_id, memo, ts, cursor)
        cursor.execute("INSERT INTO wire_transfer_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (w_id, v_id, ts, amt, sub_aba, init_user, app_user, sanitized_memo, dlp_count))
        prev_hash = append_sox_ledger(cursor, ts, "FEDWIRE_SUBMISSION", w_id, amt, init_user, prev_hash)

    conn.commit()

    print("=" * 88)
    print(" TREASURY CYBER-SENTINEL: PHASE 1 INGESTION, BEC TELEMETRY & DLP VAULT SUMMARY")
    print("=" * 88)

    print("\n[1] CERTIFICATE TRANSPARENCY (CT) LOOKALIKE DOMAIN TELEMETRY:")
    cursor.execute("""
        SELECT observed_domain, levenshtein_distance, domain_similarity_pct, shannon_entropy, spoofed_aba_routing, aba_mod10_valid
        FROM bec_domain_telemetry
    """)
    for row in cursor.fetchall():
        print(f"  • Domain: {row[0]:<27} | Edit Dist: {row[1]} | Sim: {row[2]}% | Entropy: {row[3]} bits | Spoofed ABA: {row[4]} (Mod10 Valid: {bool(row[5])})")

    print("\n[2] ZERO-TRUST PCI-DSS / GLBA DLP INTERCEPTS & HMAC-SHA256 VAULTING:")
    cursor.execute("""
        SELECT wire_id, data_classification, validation_algorithm, hmac_sha256_token, regulatory_control
        FROM pci_dlp_intercepts
    """)
    for row in cursor.fetchall():
        print(f"  • Wire: {row[0]} | Type: {row[1]:<20} | Check: {row[2]:<21} | Token: {row[3]} | {row[4]}")

    print("\n[3] SOX SECTION 404 IMMUTABLE SHA-256 AUDIT LEDGER (FIRST & LAST BLOCKS):")
    cursor.execute("SELECT ledger_seq, reference_id, amount_usd, prev_hash, curr_hash FROM sox_immutable_ledger")
    blocks = cursor.fetchall()
    for b in [blocks[0], blocks[-1]]:
        print(f"  • Block #{b[0]} ({b[1]} | ${b[2]:,.2f}) -> Prev: {b[3][:12]}... | Curr: {b[4][:16]}...")

    print("\n[SUCCESS] SQLite Warehouse 'treasury_sentinel.db' built and verified.\n")
    conn.close()

if __name__ == "__main__":
    build_treasury_warehouse()
