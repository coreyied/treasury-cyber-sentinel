# Corporate Treasury & Wire Settlement Integrity System

This project looks for signs of fraud in corporate wire payments. It catches fake vendor domains used in Business Email Compromise (BEC) scams, flags wires that were split up to get around approval limits, strips sensitive data out of payment memos, and keeps a tamper-proof SHA-256 audit log for SOX Section 404.

---

## How It's Built

- **Database (SQLite):** The schema uses window functions (`LAG() OVER`, `SUM() OVER`, `COUNT() OVER`) to group related transactions and spot clusters. It also holds the hash-chained audit log.
- **Data Collector (Python):** Handles the threat checks. It uses Levenshtein edit distance and Shannon entropy to spot lookalike domains, validates ABA routing numbers with the Federal Reserve Mod-10 checksum, and redacts card numbers using the Luhn check. Anything it redacts gets swapped for an HMAC-SHA256 token.
- **Compliance Engine (Java):** Connects to the SQLite database through JDBC and checks payment amounts using `BigDecimal`. It also verifies the audit ledger hasn't been altered and exports CSV reports that open fine in Excel or Power BI.
- **SOC Workbench (HTML/JavaScript):** A single-page dashboard where you can try out domain spoofing, test the PII scrubbing, and simulate someone tampering with the database to watch the hash chain break.

---

## Repo Layout

```text
treasury-cyber-sentinel/
├── lib/                            # External dependencies (SQLite JDBC driver)
├── sample_data/                    # Exported CSV audit reports and compliance logs
├── schema.sql                      # Tables, views, and audit ledger schema
├── treasury_threat_collector.py    # Python scraper, DLP filter, and database seeder
├── TreasurySoxAndFraudEngine.java  # Java compliance runner and report generator
├── treasury_soc_report.html        # Interactive SOC dashboard and attack simulator
└── README.md                       # You're reading it
```

---

## Getting Started

### 1. Build the database and run the Python collector

You'll need Python 3 and Java installed. Start by running the collector, which creates the SQLite database (`treasury_sentinel.db`):

```bash
python3 treasury_threat_collector.py
```

### 2. Run the Java compliance engine

This compiles and runs the Java engine. It verifies the audit chain, applies the dollar-amount rules, exports the CSV reports, and generates the HTML workbench:

```bash
javac -cp ".:lib/sqlite-jdbc-3.46.1.0.jar" TreasurySoxAndFraudEngine.java
java --enable-native-access=ALL-UNNAMED -cp ".:lib/sqlite-jdbc-3.46.1.0.jar" TreasurySoxAndFraudEngine
```

### 3. Open the workbench

Open the dashboard in your browser:

```bash
open treasury_soc_report.html
```

You can also try it online here: [coreyied.github.io/treasury-cyber-sentinel/treasury_soc_report.html](https://coreyied.github.io/treasury-cyber-sentinel/treasury_soc_report.html)

---

## What It Checks For

1. **SOX Section 404 IT General Controls:** Enforces dual authorization on wires over $50,000 and flags patterns where a large payment has been split into smaller ones.
2. **Audit Ledger Integrity:** Every transaction gets added to `sox_immutable_ledger`, and each entry's hash is built like this: `curr_hash = SHA256(timestamp | category | ref_id | amount | actor | prev_hash)`. Since each hash depends on the one before it, changing any record breaks every hash after it.
3. **BEC Lookalike Detection:** Compares incoming domains to official vendor domains using Levenshtein distance and Shannon entropy, and checks routing numbers with the Federal Reserve Mod-10 validation.
4. **PII and Card Redaction:** Scans outgoing payment memos for credit card numbers (confirmed with the Luhn algorithm), SSNs, and live API secrets, then replaces them with HMAC-SHA256 tokens.
