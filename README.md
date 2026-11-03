# PhishScope: AI-Powered Email Threat Detection & Infrastructure-Aware Forensics

**PhishScope** is an evidence-grounded web application designed for cybersecurity analysts, security operations centers (SOC), and academic researchers. It combines RFC-compliant email header forensics, SPF/DKIM/DMARC authentication analysis, URL and attachment risk modeling, infrastructure intelligence, graph correlation, and server-side Gemini AI assistance.

---

## Architecture & Design Decisions

### 1. Evidence Provenance & Transparency
Every finding in PhishScope retains full provenance:
- **Observed Facts**: Technical data directly present in the RFC 5322 message or headers.
- **Derived Findings**: Algorithmic conclusions derived from routing, alignment, or content checks.
- **Exploratory Correlation**: Infrastructure and campaign intersections that indicate common relays or hosting providers without assuming confirmed threat attribution.
- **Reasoning Chain**: Deterministic, traceable scoring logic with visible weights and uncertainty states.

### 2. Interchangeable Model Architecture (Preserving Decision 3.1)
- **Dataset and model selection remain open**: No unapproved training dataset or arbitrary ML weights are hardcoded.
- The system includes an interchangeable `IMLClassifierAdapter` registry supporting:
  - TF-IDF + Logistic Regression / Linear SVM
  - Gradient Boosted Trees (GBDT) on structured forensic indicators
  - Transformer-based email classifiers
- If no model is configured, the application clearly states: *"ML classification has not yet been configured."* It does not fabricate predictions or mock dataset performance metrics.
- A deterministic test double is included solely for software unit/regression testing.

### 3. In-Memory Session Storage & Privacy (Preserving Decision 3.2)
- **Zero permanent disk retention**: Uploaded `.eml` files and pasted content are processed in-memory in request-scoped storage.
- Raw email bodies and attachments are never stored to disk and never retained silently.
- Automatic 2-hour TTL expiration with one-click **"Wipe Session"** capability.
- Raw email bodies are not sent to third-party services or Gemini by default; Gemini receives only structured, sanitized forensic metadata.

---

## Functional Modules

- **Module A — Analyst Dashboard**: Metrics overview (Phishing, Suspicious, Legitimate, Inconclusive, Auth Warnings), recent session analyses table, empty states, and quick synthetic fixture launcher.
- **Module B — Ingestion Engine**:
  - Raw `.eml` upload (with 15MB file size boundary and safe handling).
  - Paste editor with RFC input guidance (complete message vs headers-only vs body-only).
  - Standardized synthetic test fixtures loader.
- **Module C — Email Parsing**: RFC MIME parser (`mailparser`) safely extracting envelope, headers, and computing SHA-256 attachment checksums without execution.
- **Module D — Header & SMTP Forensics**: Chronological Received-chain hop reconstruction, transit time delta analysis, RFC 1918 private vs public IP classification, candidate origin IP determination, From vs Return-Path vs Reply-To mismatches, and Message-ID consistency.
- **Module E — Authentication Forensics**: RFC 8601 `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, domain alignment evaluation, and clear provenance distinction (reported vs independently verified).
- **Module F — URL & Content Analysis**: Safe extraction, URL defanging (`hxxps://`, `[.]`), anchor display text vs href mismatch detection, direct IP URLs, unusual web ports, Punycode/IDN homoglyph detection, and shortener tracking.
- **Module G — Machine Learning Adapter**: Common interface and registry for pluggable models.
- **Module H — Infrastructure Intelligence**: Passive DNS (A, MX, published SPF TXT), reverse DNS PTR resolution, private IP safety boundaries (skips querying RFC 1918 addresses externally), and modular provider interfaces.
- **Module I — Infrastructure Graph & Correlation**:
  - Per-email node-link relationship graph (Email, Sender, Domain, Candidate IP, Relay, URL).
  - Global session correlation graph linking emails that share candidate IPs or domains with explicit exploratory caveats.
- **Module J — Evidence Fusion Engine**: Multi-signal scoring with clear uncertainty labels (`likely_phishing`, `potentially_suspicious`, `likely_legitimate`, `inconclusive`, `insufficient_evidence`).
- **Module K — Gemini Investigation Assistant**: Server-side `@google/genai` (`gemini-3.8-flash`) generating 5-pillar structured briefings (Observed Facts, Derived Findings, AI Interpretation, Unknowns, Recommended Checks) with prompt-injection defense.
- **Module L & M — Analyst Workspace & Reports**: Multi-tab investigation console, session notes editor, printable formal forensic report, and structured JSON export.
- **Module N — Settings & Health**: Model adapter switcher, provider status checks, and data hygiene controls.

---

## Automated Test Suite

Run the automated test suite from the terminal:
\`\`\`bash
npm test
\`\`\`
Or run it interactively directly from the **Automated Tests** tab in the web interface.

The suite verifies 14 core criteria:
1. RFC 1918 private IP classification (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback)
2. Public IP vs reserved link-local address classification
3. Legitimate RFC email MIME parsing
4. Graceful handling of pasted body-only input
5. Chronological normalization of SMTP Received chain
6. Negative transit time and clock reversal detection
7. SPF and DKIM pass evaluation
8. SPF failure and DMARC alignment failure evaluation
9. URL defanging for safe analyst review
10. Anchor display text vs link target mismatch detection
11. Unconfigured ML state compliance
12. Multi-email infrastructure correlation engine
13. In-memory session wipe verification
14. End-to-end pipeline evaluation of high-risk phish

---

## Development & Run Commands

\`\`\`bash
# Install dependencies
npm install

# Start the full-stack application (port 3000)
npm run dev

# Run automated tests
npm test

# Build for production
npm run build
\`\`\`
