DROP VIEW IF EXISTS v_treasury_wire_surveillance;
DROP TABLE IF EXISTS sox_immutable_ledger;
DROP TABLE IF EXISTS pci_dlp_intercepts;
DROP TABLE IF EXISTS wire_transfer_requests;
DROP TABLE IF EXISTS bec_domain_telemetry;
DROP TABLE IF EXISTS treasury_vendors;

CREATE TABLE treasury_vendors (
    vendor_id VARCHAR(16) PRIMARY KEY,
    vendor_name VARCHAR(120) NOT NULL,
    sector VARCHAR(60) NOT NULL,
    official_domain VARCHAR(100) NOT NULL,
    verified_aba_routing VARCHAR(9) NOT NULL,
    verified_account_last4 VARCHAR(4) NOT NULL,
    sox_dual_auth_limit DECIMAL(15, 2) NOT NULL
);

CREATE TABLE bec_domain_telemetry (
    telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id VARCHAR(16) NOT NULL,
    observed_domain VARCHAR(100) NOT NULL,
    levenshtein_distance INTEGER NOT NULL,
    domain_similarity_pct DECIMAL(5, 2) NOT NULL,
    shannon_entropy DECIMAL(6, 3) NOT NULL,
    has_active_mx BOOLEAN NOT NULL,
    spoofed_aba_routing VARCHAR(9) NOT NULL,
    aba_mod10_valid BOOLEAN NOT NULL,
    threat_vector VARCHAR(80) NOT NULL,
    detected_timestamp VARCHAR(30) NOT NULL,
    FOREIGN KEY (vendor_id) REFERENCES treasury_vendors(vendor_id)
);

CREATE TABLE wire_transfer_requests (
    wire_id VARCHAR(20) PRIMARY KEY,
    vendor_id VARCHAR(16) NOT NULL,
    request_timestamp VARCHAR(30) NOT NULL,
    amount_usd DECIMAL(15, 2) NOT NULL,
    submitted_aba_routing VARCHAR(9) NOT NULL,
    initiator_id VARCHAR(30) NOT NULL,
    approver_id VARCHAR(30),
    sanitized_payment_memo TEXT NOT NULL,
    dlp_redaction_count INTEGER NOT NULL,
    FOREIGN KEY (vendor_id) REFERENCES treasury_vendors(vendor_id)
);

CREATE TABLE pci_dlp_intercepts (
    intercept_id INTEGER PRIMARY KEY AUTOINCREMENT,
    wire_id VARCHAR(20) NOT NULL,
    data_classification VARCHAR(50) NOT NULL,
    validation_algorithm VARCHAR(50) NOT NULL,
    hmac_sha256_token VARCHAR(64) NOT NULL,
    regulatory_control VARCHAR(60) NOT NULL,
    intercept_timestamp VARCHAR(30) NOT NULL,
    FOREIGN KEY (wire_id) REFERENCES wire_transfer_requests(wire_id)
);

CREATE TABLE sox_immutable_ledger (
    ledger_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_timestamp VARCHAR(30) NOT NULL,
    event_category VARCHAR(40) NOT NULL,
    reference_id VARCHAR(30) NOT NULL,
    amount_usd DECIMAL(15, 2) NOT NULL,
    actor_id VARCHAR(30) NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    curr_hash VARCHAR(64) NOT NULL
);

CREATE VIEW v_treasury_wire_surveillance AS
SELECT 
    w.wire_id,
    w.vendor_id,
    v.vendor_name,
    v.sector,
    w.request_timestamp,
    w.amount_usd,
    v.sox_dual_auth_limit,
    w.initiator_id,
    COALESCE(w.approver_id, 'NONE_SINGLE_AUTH') AS approver_id,
    v.verified_aba_routing,
    w.submitted_aba_routing,
    CASE 
        WHEN w.submitted_aba_routing != v.verified_aba_routing THEN 'ROUTING_MISMATCH'
        ELSE 'VERIFIED'
    END AS routing_integrity_status,
    COALESCE(LAG(w.amount_usd) OVER (
        PARTITION BY w.vendor_id 
        ORDER BY w.request_timestamp
    ), 0.00) AS prior_wire_amount_usd,
    ROUND(SUM(w.amount_usd) OVER (
        PARTITION BY w.vendor_id
    ), 2) AS cumulative_vendor_wire_usd,
    COUNT(w.wire_id) OVER (
        PARTITION BY w.vendor_id
    ) AS vendor_wire_count,
    w.dlp_redaction_count,
    w.sanitized_payment_memo,
    COALESCE(b.observed_domain, 'NONE') AS active_bec_domain,
    COALESCE(b.levenshtein_distance, 99) AS bec_edit_distance,
    COALESCE(b.domain_similarity_pct, 0.0) AS bec_similarity_pct
FROM wire_transfer_requests w
JOIN treasury_vendors v ON w.vendor_id = v.vendor_id
LEFT JOIN bec_domain_telemetry b ON v.vendor_id = b.vendor_id;
