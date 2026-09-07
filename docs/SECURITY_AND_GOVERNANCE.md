# PhishShield: Security, Defensive Ethics & Data Governance Protocol

---

## 1. Defensive Security Mandate & Ethical Charter

PhishShield is engineered strictly as an **authorized defensive security intelligence platform**. Under no circumstances may PhishShield components be weaponized, deployed for offensive intrusions, or configured to compromise external web assets.

### Explicit Prohibitions
1. **No Defensive Control Bypass:** PhishShield must **never** disable, circumvent, or subvert standard operating system security controls, antivirus software, Google Safe Browsing, or Microsoft SmartScreen.
2. **No Offensive Payload Generation or Exploitation:** The platform does not fuzz, exploit, probe for zero-day vulnerabilities, or launch unauthorized vulnerability scans against targets.
3. **Zero Credential or Financial Asset Harvesting:** PhishShield is architected so that real user credentials, credit cards, bank account numbers, session tokens, and personal identifying information (PII) are **never** transmitted to target websites during investigation.
4. **Authorized Testing Scope:** All automated investigation, headless browser sessions, and sandbox telemetry collection must only be performed on URLs submitted by authorized users or sourced from verified public threat intelligence repositories (e.g., URLhaus, OpenPhish, PhishTank).

---

## 2. Synthetic Data Injection Protocol

To safely investigate adversarial pages that present credential-harvesting forms, two-factor authentication prompts, or fake payment gateways without leaking sensitive organizational or personal assets, PhishShield utilizes an automated **Synthetic Data Injection (SDI)** subsystem.

```
                  ┌─────────────────────────────────────────┐
                  │          Real User Environment          │
                  │ (Passwords, Cookies, Real Cards, Vault) │
                  └────────────────────┬────────────────────┘
                                       │
                              BLOCKED BY BOUNDARY
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │       PhishShield SDI Subsystem         │
                  │   (In-Memory Synthetic Data Vault)     │
                  └────────────────────┬────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
┌───────────────┐              ┌───────────────┐              ┌───────────────┐
│ Synthetic PII │              │ Synthetic CC  │              │ Synthetic Auth│
│  Full Name    │              │ Luhn-valid    │              │ Decoy Email   │
│  Mock Address │              │ Test Ranges   │              │ Mock Password │
└───────┬───────┘              └───────┬───────┘              └───────┬───────┘
        │                              │                              │
        └──────────────────────────────┼──────────────────────────────┘
                                       │ Injected into DOM
                                       ▼
                        ┌──────────────────────────────┐
                        │   Target Adversary Webpage   │
                        │    (Observed Phishing Kit)   │
                        └──────────────┬───────────────┘
                                       │
                                       ▼ (Form Submission Recorded)
                        ┌──────────────────────────────┐
                        │   Telemetry Logger Captures  │
                        │   Exfil URL, Method, Payload │
                        └──────────────────────────────┘
```

### Synthetic Asset Specifications
- **Payment Card Data:** Generated using standard sandbox test BIN ranges (e.g., VISA test card `4000 0012 3456 7890`, Mastercard test card `5105 1051 0510 5100`) with mathematically valid Luhn checksums, future expiration dates (`12/28`), and pseudo-random CVV values (`739`).
- **Identity Assets:** Uses predefined, realistic mock identities (`Alex Mercer`, `104 Security Way, Suite 400`) to evaluate whether the phishing kit performs geo-validation.
- **Decoy Credentials:** Employs cryptographically generated pseudorandom passwords prefixed with canary strings (e.g., `Decoy#9982!alpha`) to enable threat intelligence teams to track if captured decoy credentials later appear in credential dumps or dark-web leak sites.

---

## 3. Sandbox Isolation & Containment Architecture

When an investigation transitions to `HIGH` or `CRITICAL` risk, navigation cannot occur directly on the host machine. Instead, an isolated runtime environment is instantiated.

### 3.1 Containment Layers
- **Runtime Sandboxing (Docker / Linux Containers):**
  - Unprivileged user execution (`uid=10001, gid=10001`).
  - Read-only root filesystem (`--read-only`) with temporary, non-executable in-memory scratch space (`tmpfs /tmp:rw,noexec,nosuid`).
  - Strict Linux `cgroups` enforcing resource caps ($512\text{ MB}$ RAM, $0.5$ CPU core) to prevent Denial of Service via crypto-miners or fork-bombs.
  - Drop all high-risk Linux capabilities: `--cap-drop=ALL`.
  - Enforce restrictive `seccomp` and `AppArmor` profiles.
- **Network Containment & Egress Filtering:**
  - Container egress is routed strictly through the PhishShield proxy bridge.
  - Local subnet discovery (LAN, RFC 1918 private IP ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and localhost `127.0.0.1`) is blocked by default to prevent Server-Side Request Forgery (SSRF) and intranet scanning.
  - Only HTTP/HTTPS ports (`80`, `443`, `8080`, `8443`) are permitted for target inspection; outbound SMTP (`25`, `465`, `587`) is blocked to stop spambots.
- **Ephemeral Lifecycle:** Containers are destroyed immediately upon investigation completion. All session caches, memory dumps, and temporary artifacts are wiped, leaving zero persistent footprint.

---

## 4. Threat Intelligence API Governance & Terms of Service Compliance

PhishShield connects to external threat feeds while respecting third-party terms of service, intellectual property, and rate-limiting protocols:

| Provider | Purpose | Rate Limit Strategy | Fallback / Graceful Handling |
| :--- | :--- | :--- | :--- |
| **VirusTotal** | File & URL multi-engine consensus | 4 requests/min (Public tier); cached for 24 hours in Redis. | If quota exceeded, rely on local ML inference and open threat lists. |
| **URLhaus** | Real-time malware URL database | Bulk list synchronized hourly via local Redis bloom filter. | Local lookup incurs zero API overhead during live URL scan. |
| **AbuseIPDB** | IP reputation & malicious activity | 1,000 requests/day; cached for 12 hours. | Fallback to ASN-level reputation heuristics if query limit reached. |
| **RDAP / WHOIS** | Domain registration age & registrar | Throttled with exponential backoff per registrar TLD server. | Defaults to DNS TTL heuristics if RDAP server responds with HTTP 429. |
| **CT Logs (crt.sh)** | Certificate transparency analysis | Max 1 req / 2 sec per domain query. | Cached locally; queries batched asynchronously. |

---

## 5. Data Privacy, Data Minimization & Retention

1. **User Browsing Privacy:** For standard benign browsing (`LOW` risk), PhishShield does **not** log full URLs or telemetry beyond anonymized domain frequency counters to preserve end-user privacy.
2. **Investigation Retention Policy:**
   - Full DOM snapshots, network payloads, and screenshots captured during `HIGH`/`CRITICAL` investigations are stored in encrypted PostgreSQL volumes for 90 days.
   - PII filtering: In the event that an analyst accidentally inputs non-synthetic data, a client-side regex scrubber sanitizes credit cards and passwords before database ingestion.
3. **Audit Trail:** Every investigation session logs analyst ID, timestamp, target URL hash, assigned risk score, and system actions to ensure forensic accountability.
