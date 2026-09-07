# PhishShield: Cyber Threat Detection & Risk-Adaptive Secure Browsing Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security: Defensive](https://img.shields.io/badge/Security-Defensive%20Charter-green.svg)](docs/SECURITY_AND_GOVERNANCE.md)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![FastAPI: 0.110+](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![Next.js: 14](https://img.shields.io/badge/Frontend-Next.js%2014-black.svg)](https://nextjs.org)
[![Architecture: Manifest V3](https://img.shields.io/badge/Extension-Manifest%20V3-orange.svg)](docs/SYSTEM_SPECIFICATION.md)

> **DETECT. ADAPT. ISOLATE. EXPLAIN.**

PhishShield is an enterprise-grade cybersecurity platform engineered to detect suspicious and malicious web threats, quantify multidimensional risk, adapt the client-side browsing context dynamically, securely isolate high-risk targets for controlled analyst investigation, correlate underlying threat infrastructure into graph networks, and synthesize evidence-grounded threat reports through an AI-assisted security analyst.

---

## Key Differentiators

Unlike simple URL blocklists or browser antiviruses, PhishShield provides an end-to-end investigation and adaptive defense ecosystem:

1. **Risk-Adaptive Browsing:** Does not treat all websites identically. Client responses adapt automatically across four calibrated risk tiers: `LOW` (allow), `MEDIUM` (warning gate), `HIGH` (controlled investigation), and `CRITICAL` (isolated sandboxing).
2. **Synthetic Data Injection (SDI):** During high-risk investigations of phishing kits and fake payment gateways, PhishShield injects realistic, Luhn-compliant synthetic credit cards, dummy identities, and canary passwords, enabling analysts to safely observe form destinations and exfiltration endpoints without leaking real user assets.
3. **Deep Learning + Multidimensional Risk Scoring:** Combines 38-feature lexical extraction, deep character-level sequence embeddings (Char-CNN/BiLSTM), infrastructure health, domain reputation, and external threat intelligence into a normalized score ($0 - 100$).
4. **Graph-Powered Campaign Intelligence:** Ingests URLs, domains, IPs, ASNs, SSL certificates, and nameservers into a Neo4j property graph to cluster disparate attacks and expose shared adversarial infrastructure.
5. **Evidence-Grounded AI Security Analyst:** Leverages structured telemetry to generate executive and forensic investigation reports strictly partitioned into `OBSERVED`, `INFERRED`, and `UNKNOWN` evidence buckets with zero fabrication.

---

## Core System Architecture

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
│ • Feature Engine │             │ • Docker Sandbox │             │ • Neo4j Graph    │
│ • ML/DL Pipeline │             │ • Behavior Mon.  │             │ • AI Sec Analyst │
│ • Adaptive Engine│             │ • Synth. Data Inj│             │ • SOC Dashboard  │
└──────────────────┘             └──────────────────┘             └──────────────────┘
```

---

## Operating Progression

The entire platform operates along a strict defensive lifecycle:

$$\mathbf{DETECT} \longrightarrow \mathbf{ASSESS} \longrightarrow \mathbf{ADAPT} \longrightarrow \mathbf{ISOLATE} \longrightarrow \mathbf{INVESTIGATE} \longrightarrow \mathbf{CORRELATE} \longrightarrow \mathbf{EXPLAIN}$$

- **DETECT:** Deep learning & lexical feature extraction evaluate the candidate target.
- **ASSESS:** Multidimensional risk engine computes an aggregated risk score ($0 - 100$).
- **ADAPT:** Dynamic routing assigns client browsing posture (Allow, Warn, Controlled, Isolate).
- **ISOLATE:** High-risk URLs are contained in unprivileged, ephemeral Docker / Playwright containers.
- **INVESTIGATE:** Observe redirect chains, DOM mutations, network egress, and inject synthetic data.
- **CORRELATE:** Model hosting, certificate, IP, and ASN relationships inside Neo4j.
- **EXPLAIN:** AI Security Analyst provides structured, evidence-grounded reports.

---

## Multidimensional Risk Tiers

| Score Range | Threat Level | Adaptive System Response | Client Workflow |
| :---: | :---: | :--- | :--- |
| **0 – 30** | **LOW** | **Normal Browsing:** Direct navigation permitted. | Subtle green shield; passive telemetry logging. |
| **31 – 60** | **MEDIUM** | **Warning Interstitial:** Pre-navigation paused. | Displays risk breakdown; requires deliberate user confirmation. |
| **61 – 80** | **HIGH** | **Controlled Investigation:** Standard navigation blocked. | One-click launch into ephemeral container with synthetic form autofill. |
| **81 – 100** | **CRITICAL** | **Isolated Sandboxing:** Direct local access prohibited. | Executes in isolated headless container; stream telemetry to SOC dashboard. |

---

## Repository Structure

```
PhishShield-Secure-Browser/
├── backend/                  # FastAPI Application & Security Intelligence Backend
│   ├── app/
│   │   ├── api/              # REST & WebSocket Endpoints
│   │   ├── features/         # 38-feature Lexical & Structural Extractors
│   │   ├── ml/               # Model inference wrappers & calibration
│   │   ├── risk/             # Multidimensional Risk Scoring Engine
│   │   ├── sandbox/          # Playwright & Docker Isolation Orchestrator
│   │   ├── threat_intel/     # Connectors: URLhaus, AbuseIPDB, VirusTotal, RDAP
│   │   ├── graph/            # Neo4j Cypher schemas & correlation queries
│   │   └── analyst/          # Evidence-grounded AI Security Analyst prompt engine
│   └── requirements.txt      # Backend Python dependencies
├── extension/                # Manifest V3 Browser Extension (TypeScript / React)
│   ├── manifest.json         # Chrome / Chromium MV3 manifest
│   ├── src/
│   │   ├── background/       # declarativeNetRequest & webNavigation handlers
│   │   ├── popup/            # Extension UI drawer & risk badge
│   │   └── interstitial/     # Security warning gate for MEDIUM risk URLs
├── browser/                  # PhishShield Secure Dedicated Browser
│   └── src/                  # Hardened Chromium / Electron implementation
├── dashboard/                # Next.js 14 SOC Investigation Dashboard
│   └── src/                  # Threat overview, graph visualizer, telemetry timeline
├── ml/                       # Machine Learning & Deep Learning Training Pipelines
│   ├── datasets/             # Data curation scripts (PhishTank, URLhaus, Tranco)
│   ├── models/               # Model architectures (XGBoost, Char-CNN, BiLSTM)
│   └── evaluation/           # Scientific validation & benchmark scripts
├── docs/                     # Comprehensive Architecture & Specification Documentation
│   ├── SYSTEM_SPECIFICATION.md
│   ├── ARCHITECTURE_AND_DATA_FLOW.md
│   ├── SECURITY_AND_GOVERNANCE.md
│   └── ROADMAP_AND_EVALUATION.md
└── README.md                 # Project Overview & Architecture Guide
```

---

## Accelerated 2-Month (8-Week) Roadmap

- **Sprint 1 (Weeks 1–2):** Monorepo setup, dataset curation, 38-feature extractor, baseline ML & deep sequence models.
- **Sprint 2 (Weeks 3–4):** FastAPI backend, PostgreSQL schema, Risk Engine ($0-100$), and Manifest V3 Extension prototype (**MVP Release**).
- **Sprint 3 (Weeks 5–6):** Playwright sandboxing, Synthetic Data Injection (SDI), behavioral telemetry streaming, and Threat Intelligence connectors.
- **Sprint 4 (Weeks 7–8):** Neo4j infrastructure graph, campaign clustering, AI Security Analyst, and Next.js SOC Dashboard (**Advanced Release**).

See the full plan in [ROADMAP_AND_EVALUATION.md](docs/ROADMAP_AND_EVALUATION.md).

---

## Research Question

> *"Can a deep learning-based risk-adaptive secure browsing framework, combined with browser isolation, behavioral analysis, and infrastructure-level threat intelligence, enable authorized users to safely investigate suspicious websites while reducing exposure of real user resources and improving phishing campaign detection?"*

---

## Security & Ethics Charter

PhishShield is strictly defensive. It will **never**:
- Bypass Google Safe Browsing or Microsoft SmartScreen.
- Evade antivirus or deploy offensive payloads.
- Harvest or expose real user credentials, cookies, or banking information.

Detailed security and ethical standards are codified in [SECURITY_AND_GOVERNANCE.md](docs/SECURITY_AND_GOVERNANCE.md).

---

## Documentation Index

- [System Engineering Specification](docs/SYSTEM_SPECIFICATION.md): Full technical breakdown of all system modules and defensive boundaries.
- [Architecture & Data Flow](docs/ARCHITECTURE_AND_DATA_FLOW.md): Microservice architecture, component interactions, and end-to-end data pipeline.
- [Security, Ethics & Governance Protocol](docs/SECURITY_AND_GOVERNANCE.md): Synthetic data injection, container containment, and API compliance.
- [2-Month Roadmap & Scientific Evaluation](docs/ROADMAP_AND_EVALUATION.md): 8-week execution milestones and rigorous research evaluation framework.

---

## License

This project is licensed under the Apache 2.0 License.