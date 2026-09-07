# PhishShield: Accelerated 2-Month Roadmap & Scientific Evaluation Framework

---

## 1. Accelerated 2-Month (8-Week) Execution Roadmap

To rapidly transition PhishShield from conceptual architecture to a fully functional, enterprise-grade prototype, development is structured into four two-week agile sprints across an intensive 8-week delivery cycle.

```
       ┌─────────────────────────────────────────────────────────────┐
       │                   PHISHSHIELD 8-WEEK CYCLE                  │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
    ┌──────────────────┬──────────────┴─────┬──────────────────┐
    ▼                  ▼                    ▼                  ▼
[Sprint 1: W1-W2]  [Sprint 2: W3-W4]    [Sprint 3: W5-W6]  [Sprint 4: W7-W8]
Foundations &      API Core, Risk &     Sandboxing, Threat Graph, AI Analyst,
ML Detection       MV3 Extension        Intel & Telemetry  Dashboard & Eval
```

---

### Sprint 1 (Weeks 1–2): Core Architecture, Data Curation & ML/DL Detection Engine
- **Week 1: Engineering Setup & Data Engineering**
  - Establish monorepo structure (`backend/`, `extension/`, `browser/`, `dashboard/`, `ml/`).
  - Curate and preprocess verified datasets (PhishTank, URLhaus, OpenPhish, Tranco Top 1M benign domains).
  - Implement the 38-feature lexical, structural, and TLD extractor in Python (`ml/features/url_features.py`).
- **Week 2: Detection Model Training & Baseline Benchmarks**
  - Train and cross-validate baseline models: Logistic Regression, Random Forest, and XGBoost.
  - Implement deep sequence model (Character-CNN/BiLSTM) for raw URL sequence embeddings.
  - Calibrate output probabilities via Isotonic Regression / Platt Scaling.
  - Export optimized model weights (ONNX / Joblib) for ultra-fast production inference.

---

### Sprint 2 (Weeks 3–4): FastAPI Backend, Risk Engine & MV3 Extension Prototype
- **Week 3: FastAPI Backend & PostgreSQL Core**
  - Build asynchronous FastAPI service (`/api/v1/scan/url`, `/api/v1/investigations`).
  - Configure PostgreSQL database schema (investigations, URLs, users, scan events) and Redis cache.
  - Implement Multidimensional Risk Engine ($0-100$ scoring algorithm with adaptive verdict routing).
- **Week 4: PhishShield Browser Extension (Manifest V3)**
  - Implement Chrome/Edge MV3 extension in TypeScript and React.
  - Add pre-navigation URL interception via `chrome.declarativeNetRequest` and `webNavigation`.
  - Implement floating risk badge, interactive popup drawer, and full-screen warning interstitial page for `MEDIUM` risk URLs.
  - Connect extension to FastAPI backend with local caching.

---

### Sprint 3 (Weeks 5–6): Headless Playwright Sandbox, Behavioral Telemetry & Threat Feeds
- **Week 5: Ephemeral Sandboxing & Synthetic Data Injection**
  - Develop Dockerized Playwright agent with unprivileged execution, read-only root, and network egress controls.
  - Implement **Synthetic Data Injection (SDI)**: auto-detect form inputs and inject valid Luhn test credit cards, mock credentials, and dummy PII.
  - Capture runtime DOM mutations, multi-hop HTTP redirects, and outbound network waterfalls.
- **Week 6: Threat Intelligence Connectors & Enrichment**
  - Build asynchronous API clients for VirusTotal, URLhaus, AbuseIPDB, and RDAP/WHOIS.
  - Implement Redis-backed Bloom filters for instant local lookup of known malicious domains.
  - Ingest dynamic sandbox behavioral telemetry into PostgreSQL event timeline tables.

---

### Sprint 4 (Weeks 7–8): Neo4j Threat Graph, AI Security Analyst & SOC Dashboard
- **Week 7: Neo4j Infrastructure Graph & Campaign Clustering**
  - Configure Neo4j instance and write Cypher ingestion pipelines for URLs, Domains, IPs, ASNs, Certificates, and Nameservers.
  - Implement campaign clustering algorithms to identify shared adversarial hosting patterns.
  - Distinguish strictly between `CONFIRMED` and `INFERRED` graph edges.
- **Week 8: AI Security Analyst, SOC Dashboard & Final System Validation**
  - Implement AI Security Analyst engine with strict prompt grounding: outputs partitioned into `OBSERVED`, `INFERRED`, and `UNKNOWN`.
  - Finalize Next.js SOC Dashboard (risk overview, live investigation timeline, interactive Neo4j graph viewer, AI report generator).
  - Run end-to-end integration tests, benchmarks, and generate the final scientific evaluation report.

---

## 2. Deliverables by Version Tier

| Tier | Delivery Target | Included Capabilities |
| :--- | :--- | :--- |
| **MVP (Minimum Viable Product)** | End of Week 4 | - Complete ML Feature Extraction & XGBoost inference engine.<br>- FastAPI backend with PostgreSQL & Redis.<br>- Manifest V3 Extension with live URL interception and warning interstitials.<br>- Multidimensional Risk Scoring Engine ($0-100$). |
| **Advanced System** | End of Week 8 | - Dockerized Playwright Sandbox with Synthetic Data Injection.<br>- Full behavioral telemetry recorder (redirects, DOM, network exfiltration).<br>- External Threat Intelligence connectors (URLhaus, AbuseIPDB, VT).<br>- Neo4j Infrastructure Graph & Campaign Clustering.<br>- Evidence-grounded AI Security Analyst engine.<br>- Full Next.js Analyst Security Dashboard. |
| **Enterprise / SOC Vision** | Post 2-Month Roadmap | - Native Chromium/Electron hardened secure browser distribution.<br>- Multi-tenant RBAC & SIEM/SOAR integration (Splunk, Sentinel, Cortex XSOAR).<br>- Hardware-virtualized micro-VM isolation (Firecracker/gVisor).<br>- Continual online learning and automated model retraining pipelines. |

---

## 3. Scientific Evaluation Framework

### 3.1 Research Question
> *"Can a deep learning-based risk-adaptive secure browsing framework, combined with browser isolation, behavioral analysis, and infrastructure-level threat intelligence, enable authorized users to safely investigate suspicious websites while reducing exposure of real user resources and improving phishing campaign detection?"*

### 3.2 Evaluation Metrics & Rigor

Under no circumstances are evaluation metrics or benchmark numbers fabricated. All published results must be obtained from reproducible validation scripts.

#### A. Machine Learning & Detection Performance
- **Primary Metrics:** Precision, Recall, F1-Score, Balanced Accuracy, ROC-AUC.
- **Error Bounds:** False Positive Rate (FPR) on legitimate banking/tech portals must remain $< 0.1\%$; False Negative Rate (FNR) on active phishing kits evaluated.
- **Inference Latency:** Target $< 20\text{ ms}$ for feature extraction and model inference to ensure zero noticeable browsing latency.
- **Temporal Generalization:** Evaluate models across chronologically separated test sets to measure drift resilience.

#### B. Security & Containment Validation
- **Asset Exposure Rate:** Verify that in $100\%$ of test cases with synthetic injection enabled, zero real user cookies, passwords, or IP addresses are leaked to target web forms.
- **Sandbox Containment:** Audit Docker container boundaries to verify no unauthorized local network (RFC 1918) traversals or filesystem escapes can occur.

#### C. Graph Correlation & Campaign Intelligence
- **Clustering Accuracy:** Measure precision of identified campaign nodes against ground-truth security threat reports.
- **Edge Provenance:** Validate strict categorization of confirmed DNS relationships versus candidate/inferred infrastructure links.

#### D. AI Analyst Grounding
- **Hallucination Rate:** Measure instances where the AI outputs indicators (IPs, hashes, domain names) not present in the verified investigation evidence JSON. Target: $0.0\%$.
- **Adherence to Evidence Triad:** Validate that $100\%$ of generated assertions are categorized into `OBSERVED`, `INFERRED`, or `UNKNOWN`.
