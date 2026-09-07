# PhishShield: System Engineering Specification
## A Deep Learning-Based Cyber Threat Detection & Risk-Adaptive Secure Browsing Platform

---

### Document Information
- **Classification:** Enterprise Defensive Cybersecurity Specification / Engineering Design Document
- **Project Name:** PhishShield
- **Full Title:** PhishShield: A Deep Learning-Based Cyber Threat Detection & Risk-Adaptive Secure Browsing Platform
- **Domain:** Cybersecurity, Artificial Intelligence, Deep Learning, Secure Browsing, Threat Intelligence, Graph Intelligence, SOC Operations
- **Core Tagline:** `DETECT. ADAPT. ISOLATE. EXPLAIN.`

---

## 1. Executive Summary & Product Identity

PhishShield is an enterprise-grade defensive cybersecurity platform engineered to detect suspicious and malicious web threats, quantify multidimensional risk, adapt the client-side browsing context dynamically, securely isolate high-risk targets for controlled analyst investigation, correlate underlying threat infrastructure into graph networks, and synthesize evidence-grounded threat reports through an AI-assisted security analyst.

PhishShield addresses the full lifecycle across two synchronized client products sharing a centralized backend intelligence core:
1. **PhishShield Secure Browser:** A hardened, dedicated Chromium/Electron-based analyst browser featuring native risk evaluation, isolated sandboxing, and telemetry instrumentation.
2. **PhishShield Browser Extension:** A lightweight Manifest V3 cross-browser extension providing real-time URL interception, client-side risk warnings, and one-click delegation to the secure backend sandbox.

```
                    ┌──────────────────────────────────────────────┐
                    │                  PHISHSHIELD                 │
                    │        Defensive Intelligence Platform       │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │                                              │
         ┌─────────────────────┐                        ┌─────────────────────┐
         │ PHISHSHIELD SECURE  │                        │ PHISHSHIELD BROWSER │
         │       BROWSER       │                        │      EXTENSION      │
         │ (Chromium/Electron) │                        │    (MV3 / React)    │
         └──────────┬──────────┘                        └──────────┬──────────┘
                    │                                              │
                    └──────────────────────┬───────────────────────┘
                                           │ API / WebSockets
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │               SECURITY BACKEND               │
                    │         (FastAPI / Postgres / Redis)         │
                    └──────────────────────┬───────────────────────┘
                                           │
         ┌─────────────────────────────────┴─────────────────────────────────┐
         ▼                                 ▼                                 ▼
┌──────────────────┐             ┌──────────────────┐             ┌──────────────────┐
│ DETECTION & RISK │             │  INVESTIGATION   │             │   INTELLIGENCE   │
│ • Feature Engine │             │ • Docker / Playw.│             │ • Neo4j Graph    │
│ • ML/DL Pipeline │             │ • Behavior Mon.  │             │ • AI Sec Analyst │
│ • Adaptive Engine│             │ • Synth. Data Inj│             │ • SOC Dashboard  │
└──────────────────┘             └──────────────────┘             └──────────────────┘
```

---

## 2. Core Operating Philosophy

Every event within PhishShield executes strictly according to the defensive progression:

$$\mathbf{DETECT} \longrightarrow \mathbf{ASSESS} \longrightarrow \mathbf{ADAPT} \longrightarrow \mathbf{ISOLATE} \longrightarrow \mathbf{INVESTIGATE} \longrightarrow \mathbf{CORRELATE} \longrightarrow \mathbf{EXPLAIN}$$

- **DETECT:** Intercept candidate URLs and inspect lexical, structural, and real-time page features using machine learning and deep learning sequence models.
- **ASSESS:** Synthesize threat probabilities, infrastructure signals, behavioral indicators, and threat feeds into a normalized, calibrated risk index ($0 - 100$).
- **ADAPT:** Determine the browsing posture dynamically (Normal $\rightarrow$ Warn $\rightarrow$ Controlled $\rightarrow$ Isolated).
- **ISOLATE:** Detach high-threat target interactions into ephemeral, segregated sandboxes (Docker / hardened browser instances) to prevent credential, session, and filesystem leakage.
- **INVESTIGATE:** Safely trigger form elements, observe multi-stage redirects, monitor background network requests, and record DOM mutations under instrumented monitoring.
- **CORRELATE:** Ingest DNS, IP, ASN, SSL/TLS certificates, and nameservers into Neo4j graph schemas to uncover shared hosting patterns and adversarial campaign clusters.
- **EXPLAIN:** Deploy an evidence-grounded AI Security Analyst that contextualizes technical telemetry into structured narratives strictly partitioned by `OBSERVED`, `INFERRED`, and `UNKNOWN` evidence buckets.

---

## 3. Problem Statement & Enterprise Threat Landscape

Modern adversaries leverage ephemeral infrastructure, bulletproof hosting, multi-tier redirect chains, dynamic cloaking, and credential-harvesting kits that frequently evade traditional static blocklists. While tools like Google Safe Browsing and Microsoft SmartScreen offer foundational perimeter blocking, security analysts, incident responders, and high-risk enterprise personnel frequently need to:
1. Investigate zero-day or uncataloged suspicious links without exposing real corporate assets.
2. Intercept credential phishing and fake payment gateways without leaking legitimate credentials or banking details.
3. Trace multi-hop infrastructure to reveal threat actors, related domains, and active campaigns.
4. Bridge the gap between low-level telemetry (pcap, DOM dumps, DNS logs) and actionable SOC reporting.

Directly inspecting suspicious URLs in a standard browser exposes:
- Real corporate credentials and single sign-on (SSO) session tokens.
- Authentication cookies and local storage tokens.
- Internal corporate IP addresses and network topologies.
- Local workstation filesystems through zero-day drive-by downloads or browser vulnerabilities.

PhishShield resolves this by decoupling the end user from dangerous threat surfaces through **risk-adaptive containment** and **synthetic data injection**.

---

## 4. Fundamental Defensive Principles & Synthetic Data Protocol

> [!IMPORTANT]
> **Strict Defensive Posture:** PhishShield is engineered exclusively as a defensive security and incident analysis system. It is explicitly prohibited from:
> - Circumventing or disabling browser security mechanisms (Google Safe Browsing, SmartScreen, CSP).
> - Evading security controls or launching offensive scans.
> - Deploying offensive payloads or testing exploit payloads against external targets.
> - Capturing, storing, or transmitting real user passwords, cookies, or financial cards.

### Synthetic Data Injection Architecture
When an analyst or high-risk session navigates a page containing credential-harvesting or payment fields in an isolated sandbox, PhishShield's agent automatically replaces sensitive user inputs with cryptographically generated **synthetic test data**:

```
[Real User Profile / Vault]  ──(BLOCKED / NEVER EXPOSED)──x  [Phishing Form]
                                                                    ▲
[Synthetic Data Generator]   ──(Valid Luhn Card / Fake PII)────────┘
                                     │
                                     ▼
                            [Telemetry Recorder]
                     (Captures C2 POST endpoint & payload)
```

1. **Payment Gateways:** Generates synthetic credit card numbers adhering to Luhn algorithm validation (e.g., test ranges like `4000 0012 3456 7890`), realistic test expiration dates, and test CVVs.
2. **Identity & Passwords:** Injects disposable persona credentials (`analyst_probe_8472@synthetic-test.local`, randomized mock strings).
3. **Observation Outcome:** The platform records form action targets, obfuscated POST destinations, intermediate beacon URLs, and post-submission redirects without risking any actual asset.

---

## 5. Architectural Modules Breakdown

### Module 1: Secure Browser Module (Dedicated Client)
- Built on Chromium using Electron with custom isolation controls.
- Enforces session compartmentalization: memory-only cache, zero cookie persistence across domains, disabled WebRTC local IP enumeration, and mandatory egress routing through the PhishShield security proxy.
- Features integrated risk indicators, navigation barrier dialogs, and native timeline rendering.

### Module 2: Browser Extension Module (Cross-Browser)
- Developed targeting Chrome/Edge/Firefox Manifest V3 using TypeScript and React.
- Hooks `declarativeNetRequest` and `webNavigation` to intercept pre-navigation events.
- Queries the backend risk engine asynchronously, overlaying inline safety badges, threat drawer panels, and warning screens before malicious page loads execute.

### Module 3: Feature Extraction Module
Collects high-dimensional signals across four discrete domains:

| Category | Extracted Signals |
| :--- | :--- |
| **URL Lexical** | URL length, subdomain count, Shannon entropy, presence of `@`, `//`, hyphen frequency, IP-in-hostname, tld reputation, suspicious brand tokens (e.g., `paypal-verify`, `apple-id-security`), Unicode punycode/homoglyph markers. |
| **Domain / DNS** | Domain age (via RDAP/WHOIS), registrar details, DNS TTL variance, A/AAAA record churn, authoritative nameserver reputation. |
| **DOM / Page** | Presence of password inputs, credit card inputs, external iframe embeddings, form `action` pointing to differing domains, hidden DOM elements, zero-pixel iframes, obfuscated JavaScript (eval, unescape). |
| **Infrastructure** | Resolving IPv4/IPv6, Autonomous System Number (ASN), AS Organization, reverse DNS PTR, SSL/TLS issuer, validity window, SAN (Subject Alternative Names) count. |

### Module 4: ML/DL Threat Detection Engine
A multi-tier detection architecture prioritizing low-latency inference and sequence robustness:
- **Baseline Tier:** Logistic Regression and Random Forest models evaluating curated tabular lexical features.
- **Advanced Machine Learning:** Gradient-boosted decision trees (XGBoost / LightGBM) trained on multi-source URL feature vectors.
- **Deep Learning Tier:** Character-level Convolutional Neural Networks (Char-CNN) / BiLSTM or lightweight Transformer encoder models processing raw URL character sequences to catch zero-day obfuscation and algorithmic domain generation (DGA).
- **Ensemble & Calibration:** Model probabilities calibrated using Platt Scaling or Isotonic Regression to ensure outputs represent realistic threat probabilities rather than uncalibrated confidence spikes.

### Module 5: Multidimensional Risk Scoring Engine
The system aggregates heterogeneous evidence into a unified Risk Index ($R \in [0, 100]$):

$$R = w_1 \cdot P_{\text{ML}} + w_2 \cdot S_{\text{Domain}} + w_3 \cdot S_{\text{Infra}} + w_4 \cdot S_{\text{Behavior}} + w_5 \cdot S_{\text{ThreatIntel}}$$

*Initial design assumption weights (subject to empirical calibration):*
- **ML/DL Threat Probability ($P_{\text{ML}}$):** 40%
- **Domain Reputation ($S_{\text{Domain}}$):** 20%
- **Infrastructure Risk ($S_{\text{Infra}}$):** 15%
- **Observed Dynamic Behavior ($S_{\text{Behavior}}$):** 15%
- **External Threat Feeds ($S_{\text{ThreatIntel}}$):** 10%

#### Risk Classification Tiers & Adaptive Actions

| Risk Score | Threat Level | Adaptive System Response | User/Analyst Workflow |
| :---: | :---: | :--- | :--- |
| **0 – 30** | **LOW** | **Normal Browsing:** Direct navigation allowed. Telemetry logged. | Transparent browsing with subtle green shield icon. |
| **31 – 60** | **MEDIUM** | **Warning Gate:** Navigation paused. Security interstitial displayed. | User must explicitly confirm intent to bypass. Warnings highlight detected heuristics. |
| **61 – 80** | **HIGH** | **Controlled Investigation:** Standard access blocked. One-click routing to sandbox. | Executes within an ephemeral container with synthetic credentials enabled. |
| **81 – 100** | **CRITICAL** | **Isolated Sandboxing:** Direct client access strictly forbidden. Full containment. | Run entirely in isolated Docker/VM instance with deep network egress recording. |

### Module 6: Secure Isolation & Behavior Monitoring Module
- **Automation Engine:** Playwright/Chromium running inside unprivileged, ephemeral Docker containers or VM environments with strict Linux cgroups, seccomp profiles, and non-root user execution.
- **Telemetry Event Stream:**
  1. *Browser Events:* Multi-stage redirect sequences, popup generation, new window creation, alert dialog triggers.
  2. *Page Events:* Dynamic DOM mutations, hidden iframe insertion, keyboard event logging hooks, form submission interceptors.
  3. *Network Events:* Complete request/response log, TLS handshake details, external asset origins, WebSocket connections, data exfiltration endpoints.
  4. *Download Inspection:* Intercepts downloaded blobs, hashes binaries (SHA-256), extracts MIME types, and passes metadata to static scanners.

### Module 7: Threat Intelligence & Enrichment
- Integrates authorized connectors to standard intelligence providers:
  - **URLhaus:** Real-time malware URL feeds and active malware hosting flags.
  - **VirusTotal API:** Multimodal engine consensus reports (subject to API rate limits).
  - **AbuseIPDB:** IP reputation scores, recent attack reports, subnet confidence.
  - **RDAP / WHOIS:** Registration timeline and registrar validation.
  - **Certificate Transparency (CT) Logs:** Discovery of lookalike certificates issued across Let's Encrypt, ZeroSSL, etc.

### Module 8: Neo4j Infrastructure Graph & Campaign Intelligence
Represents the cyber threat landscape as a property graph to detect shared adversarial infrastructure:

```
[URL: Target] ──HOSTED_ON──> [DOMAIN: DomainName]
[DOMAIN]      ──RESOLVES_TO──> [IP: Address]
[IP]          ──BELONGS_TO───> [ASN: Number]
[DOMAIN]      ──USES_CERT────> [CERTIFICATE: Thumbprint]
[DOMAIN]      ──USES_NS──────> [NAMESERVER: Host]
[DOMAIN]      ──RELATED_TO───> [DOMAIN: Lookalike]
[URL]         ──PART_OF──────> [CAMPAIGN: ClusterID]
```

- **Inference Separation:** Explicitly distinguishes **CONFIRMED** relationships (e.g., DNS A-record lookup observed directly) from **INFERRED/CANDIDATE** associations (e.g., shared nameserver or certificate subject match).
- Detects campaign clusters: identifies when 15 disparate phishing domains share an identical /24 IP subnet and single dynamic DNS nameserver.

### Module 9: Evidence-Grounded AI Security Analyst
Transforms dense, heterogeneous event logs into structured analyst reports. Enforces the strict **Evidence Triad**:
1. **OBSERVED:** Tangible facts verified by logs (e.g., *"The page submitted form inputs containing synthetic credit card numbers to `https://exfil-api.xyz/collect` over HTTP POST."*).
2. **INFERRED:** Deductive security reasoning based on observations (e.g., *"The combination of an unauthenticated PayPal logo and direct exfiltration to a non-PayPal domain strongly suggests credential harvesting."*).
3. **UNKNOWN:** Missing or inaccessible data (e.g., *"The registrant identity is masked by privacy services; the ultimate threat actor identity cannot be established."*).

Zero hallucination tolerance: Under no circumstances does the engine fabricate IPs, hashes, or indicators.

### Module 10: Security Dashboard & Reporting
- Built using Next.js, React, Tailwind CSS, and Recharts.
- Real-time investigation timeline, interactive Neo4j graph viewer, risk breakdown dials, raw network waterfall logs, and one-click export to PDF, JSON, and STIX 2.1 schemas.

---

## 6. Research Hypotheses & Scientific Rigor

### Primary Research Question
> *"Can a deep learning-based risk-adaptive secure browsing framework, combined with browser isolation, behavioral analysis, and infrastructure-level threat intelligence, enable authorized users to safely investigate suspicious websites while reducing exposure of real user resources and improving phishing campaign detection?"*

### Experimental Commitments
- **No Fabricated Performance:** All metrics reported (Accuracy, Precision, Recall, F1, ROC-AUC, FPR/FNR) must derive from empirical validation runs on public and enterprise datasets (e.g., PhishTank, URLhaus, Tranco top 1M).
- **Temporal Generalization Testing:** Models must be evaluated on time-separated splits (training on month $t$, testing on month $t+1$) to benchmark resistance against concept drift.
- **Fair Baseline Benchmarks:** Evaluate standard heuristics against XGBoost and character sequence neural networks to prove whether deep learning brings statistically significant performance gains.
