Plaintext
# Corporate Treasury & Wire Settlement Integrity System

Production-grade cross-language treasury surveillance pipeline designed to detect Business Email Compromise (BEC) lookalike domains, prevent unauthorized wire structuring, enforce PCI-DSS/GLBA data loss prevention (DLP), and maintain an immutable SHA-256 SOX Section 404 audit ledger.

---

## Architecture & Technology Stack

* **Database Layer:** SQLite relational schema featuring custom window functions (`LAG() OVER`, `SUM() OVER`, `COUNT() OVER`) for multi-tier transaction clustering and an immutable hash-chained audit log.
* **Ingestion & Threat Scraper (Python):** Implements dynamic programming Levenshtein edit distance, Shannon entropy calculations, Federal Reserve Mod-10 ABA routing checksum validation, and Luhn Mod-10 PII/PCI redaction with cryptographic HMAC-SHA256 vaulting.
* **Compliance & Scoring Engine (Java JDBC):** Connects to the SQLite warehouse using `java.sql`, executes `BigDecimal` monetary validation rules, verifies the cryptographic integrity of the SHA-256 audit ledger, and exports Power BI/Excel-ready CSV compliance reports.
* **Interactive SOC Workbench (HTML5/JavaScript):** Single-page audit dashboard allowing reviewers to test live domain spoofing, test PII regex scrubbing, and simulate rogue database tampering against the SHA-256 hash chain.

---

## Repository Structure

treasury-cyber-sentinel/
├── lib/                        # External dependencies (SQLite JDBC driver)
├── sample_data/                # Exported CSV audit reports & compliance logs
├── schema.sql                  # Relational tables, views, and audit ledger schema
├── treasury_threat_collector.py # Python telemetry scraper, DLP filter, & DB seeder
├── TreasurySoxAndFraudEngine.java # Java JDBC compliance runner & report generator
├── treasury_soc_report.html    # Interactive browser-based SOC & attack simulator
└── README.md                   # Project documentation

---

## Quick Start & Local Execution

### 1. Build the Database & Run Python Threat Telemetry
Make sure Python 3 and Java are installed, then run the threat collector to initialize the SQLite warehouse (`treasury_sentinel.db`):
```bash
2. Run the Java JDBC Compliance Engine
Compile and execute the Java engine to verify the SHA-256 audit chain, enforce financial thresholds, export CSV surveillance outputs, and generate the interactive HTML workbench:

Bash
javac -cp ".:lib/sqlite-jdbc-3.46.1.0.jar" TreasurySoxAndFraudEngine.java
java --enable-native-access=ALL-UNNAMED -cp ".:lib/sqlite-jdbc-3.46.1.0.jar" TreasurySoxAndFraudEngine
3. Open the Interactive Workbench
Launch the dashboard locally in your default web browser:

Bash
open treasury_soc_report.html
(Or test it live via GitHub Pages: coreyied.github.io/treasury-cyber-sentinel/treasury_soc_report.html)

Core Security & Compliance Rules Enforced
SOX Section 404 IT General Controls (ITGC): Enforces dual-authorization limits ($50,000 threshold) and flags split-wire structuring patterns.

Cryptographic Ledger Integrity: Every transaction event appends to sox_immutable_ledger, where curr_hash = SHA256(timestamp | category | ref_id | amount | actor | prev_hash). Any unauthorized database mutation instantly breaks the hash cascade.

BEC Lookalike Detection: Calculates Levenshtein distance and Shannon entropy against official vendor domains combined with Federal Reserve Mod-10 routing validation.

Zero-Trust PII & Card Redaction: Automatically screens outbound payment memos for unmasked credit cards (verified via Luhn algorithm), SSNs, and live API secrets, replacing them with HMAC-SHA256 tokens.
