# REGULATORY.md

| Field | Value |
|---|---|
| **Document** | REGULATORY.md — Regulatory Landscape & Compliance Standards |
| **Version** | 1.0.0 |
| **Parent** | TEAMS.md v1.3.0 |
| **Last Modified** | 2026-03-04 |

---

## How This Document Is Used

When TEAMS.md is loaded alongside this file, the following roles reference it directly:

- **Legal Adversary** — checks whether the design could be interpreted as negligence under applicable regulations.
- **Skeptical Auditor** — checks whether evidence and audit trails meet the standards listed here.
- **The Policeman** — checks whether enforcement matches regulatory requirements, not just internal policy.
- **Elephant** — checks whether the audit trail will satisfy regulators in 5 years.
- **The Archivist** — checks whether records meet retention and readability requirements.
- **Tortoise** — checks whether hardening meets the standard under sustained scrutiny.
- **The Database Engineer** — checks whether data handling meets integrity and sovereignty requirements.
- **The Librarian** — checks whether documentation matches behavior, because regulators will check.

**If a regulatory regime is marked as "Applies" below, every review must include at least one finding that addresses compliance with that regime.** Silence on an applicable regulation is a finding in itself.

---

## 1. Active Regulatory Regimes

*(Mark each as Applies / Does Not Apply / Under Evaluation. If "Applies," all relevant roles must address it.)*

### 1.1 Data Protection & Privacy

| Standard | Status | Notes |
|---|---|---|
| **GDPR** (EU General Data Protection Regulation) | Applies | Data processing, consent, right to deletion, breach notification (72h), DPO requirement, data processing agreements. Fines up to 4% of annual global turnover. |
| **BDSG** (Bundesdatenschutzgesetz — German Federal Data Protection Act) | Applies | German implementation of GDPR with additional provisions. Employee data protection, video surveillance rules. |
| **ePrivacy Directive** (EU) | Applies | Cookie consent, electronic communications privacy. Pending ePrivacy Regulation replacement. |

### 1.2 Information Security

| Standard | Status | Notes |
|---|---|---|
| **ISO 27001** | Applies | Information security management system. Certification requires annual audits. |
| **BSI IT-Grundschutz** | Applies | German Federal Office for Information Security baseline protection. More prescriptive than ISO 27001. |
| **NIS2 Directive** (EU) | Applies | Network and information security. Expanded scope, stricter penalties. Applies from October 2024. Incident reporting within 24h. |
| **SOC 2 (Type I & II)** | Applies | Service organization controls. Often required by enterprise clients. Type II requires sustained compliance over time. |
| **C5** (Cloud Computing Compliance Criteria Catalogue) | Applies | BSI's cloud security standard. Required for German public sector cloud. |
| **Common Criteria (ISO 15408)** | Applies | International security evaluation standard. |

### 1.3 Accessibility

| Standard | Status | Notes |
|---|---|---|
| **European Accessibility Act (EAA)** | Applies | EU directive requiring digital products and services to meet accessibility standards. Enforcement from June 2025. |
| **BFSG** (Barrierefreiheitsstärkungsgesetz) | Applies | German implementation of EAA. Applies to products and services placed on the market after June 28, 2025. |
| **WCAG 2.2** (Level AA) | Applies | Web Content Accessibility Guidelines. De facto technical standard for EAA/BFSG compliance. |
| **BITV 2.0** | Applies | German federal accessibility regulation for public sector websites. Based on WCAG. |
| **EN 301 549** | Applies | European standard for ICT accessibility. Referenced by EAA. |

### 1.4 AI & Algorithmic Systems

| Standard | Status | Notes |
|---|---|---|
| **EU AI Act** | Applies | Risk-based regulation of AI systems. High-risk categories require conformity assessments, documentation, human oversight. Phased enforcement 2024–2027. |
| **ISO 42001** | Applies | AI management system standard. Framework for responsible AI development. |

### 1.5 Financial Services

*(Not applicable — Quotico uses virtual currency only, no real-money transactions.)*

| Standard | Status | Notes |
|---|---|---|
| **PCI-DSS** | Does Not Apply | No payment card processing. Virtual points only. |
| **PSD2 / PSD3** | Does Not Apply | No payment services. |
| **DORA** (Digital Operational Resilience Act) | Does Not Apply | Not a financial entity. |
| **BaFin** regulations | Does Not Apply | Not a regulated financial service. |
| **MiFID II** | Does Not Apply | No financial instruments. |
| **SOX** (Sarbanes-Oxley) | Does Not Apply | Not US-listed. |

### 1.6 Healthcare

*(Not applicable — Quotico is a sports prediction platform.)*

| Standard | Status | Notes |
|---|---|---|
| **MDR** (EU Medical Device Regulation) | Does Not Apply | Not a medical device. |
| **IEC 62304** | Does Not Apply | Not medical software. |
| **DiGA** (Digitale Gesundheitsanwendungen) | Does Not Apply | Not a digital health application. |
| **gematik** standards | Does Not Apply | Not health infrastructure. |
| **HIPAA** | Does Not Apply | No health data processed. |
| **HL7 FHIR** | Does Not Apply | No healthcare interoperability. |

### 1.7 Automotive / Industrial

*(Not applicable — Quotico is a sports prediction platform.)*

| Standard | Status | Notes |
|---|---|---|
| **ISO 26262** | Does Not Apply | Not automotive software. |
| **IEC 62443** | Does Not Apply | Not industrial control systems. |
| **UNECE R155/R156** | Does Not Apply | Not vehicle software. |

### 1.8 Government / Public Sector

*(Not applicable unless selling to public sector.)*

| Standard | Status | Notes |
|---|---|---|
| **BSI IT-Grundschutz** | Under Evaluation | May apply if targeting public-sector clients. |
| **C5** | Under Evaluation | May apply if hosting on cloud for public-sector clients. |
| **FedRAMP** | Does Not Apply | No US government scope. |

---

## 2. Regulatory Bodies

Reference list of authorities that may audit, certify, or enforce.

| Body | Jurisdiction | Scope |
|---|---|---|
| **BSI** (Bundesamt für Sicherheit in der Informationstechnik) | Germany | IT security, certification, IT-Grundschutz, C5 |
| **BfDI** (Bundesbeauftragter für den Datenschutz) | Germany | Federal data protection supervision |
| **LfDI Sachsen** | Saxony | State-level data protection authority (your jurisdiction) |
| **ENISA** | EU | Cybersecurity agency, NIS2 coordination |
| **European Commission** | EU | GDPR enforcement coordination, AI Act |

---

## 3. Compliance Checklist Integration

For every Tier 1 review, the output template should include:

### Regulatory Compliance Check

For each regime marked "Applies":
- **Regime**: *(name)*
- **Relevant requirement**: *(specific clause or obligation)*
- **Current status**: *(compliant / non-compliant / not yet assessed)*
- **Gap**: *(what is missing)*
- **Risk if unaddressed**: *(fine, audit failure, market access blocked)*

---

## 4. Data Sovereignty & Residency

| Question | Answer |
|---|---|
| Where must data be stored? | EU (Germany preferred). Production MongoDB runs on Hetzner DE. |
| Where must data be processed? | EU only. No cross-border processing. |
| Are there restrictions on sub-processors? | Sportmonks (UK/EU) for sports data. No PII shared with sub-processors. |
| Is cross-border transfer required? | No. All user data stays within EU. |
| If yes, under what mechanism? (SCCs, adequacy decision) | N/A |

---

## 5. Retention & Deletion

| Data Category | Retention Period | Legal Basis | Deletion Process |
|---|---|---|---|
| User accounts | Until deletion requested | Art. 6(1)(b) GDPR — contract | `DELETE /api/gdpr/account` — anonymizes PII, retains anonymized records |
| Refresh tokens | 7 days (configurable) | Art. 6(1)(b) GDPR — contract | MongoDB TTL index on `expires_at` (auto-delete) |
| Access token blocklist | Until token expiry (15 min) | Art. 6(1)(f) GDPR — security | MongoDB TTL index on `expires_at` (auto-delete) |
| Betting slips & predictions | Indefinite (anonymized on account deletion) | Art. 6(1)(b) GDPR — contract | Anonymized via GDPR deletion endpoint |
| Raw odds data | 730 days | Art. 6(1)(f) GDPR — legitimate interest | MongoDB TTL index on `fetched_at` |
| Event bus monitor stats | Configurable (default 7 days) | Art. 6(1)(f) GDPR — operations | MongoDB TTL index on `ts` |
| Match/prediction archives | 90 days | Art. 6(1)(f) GDPR — data integrity | MongoDB TTL index on `archived_at` |
| API usage analytics | 90 days | Art. 6(1)(f) GDPR — operations | MongoDB TTL index on `ts` |
| Security audit logs | Indefinite | Art. 6(1)(f) GDPR — security, Art. 5(2) accountability | Available via `GET /api/gdpr/security-log` |
| Query/page caches | Self-expiring (varies) | Art. 6(1)(f) GDPR — performance | MongoDB TTL index on `expires_at` |
| Device fingerprints | Stored as hashes only | Art. 6(1)(f) GDPR — anti-fraud | Anonymized on account deletion |
| IP addresses | Stored as hashes only in logs | Art. 6(1)(f) GDPR — security | Not reversible (one-way hash) |

---

*This document is a living checklist. It should be reviewed whenever the project enters a new market, adds a new data category, or a regulatory deadline approaches.*