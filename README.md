cat << 'EOF' > ~/AbhayRecon/README.md
# 🔍 AbhayRecon - Multi-Vector Passive Attack Surface Engine

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Linux-red.svg)
![Type](https://img.shields.io/badge/Recon-Passive%20OSINT-green.svg)
![Author](https://img.shields.io/badge/Author-Abhay%20Verma-orange.svg)

**AbhayRecon** is a modular, high-speed CLI reconnaissance and defensive posture auditing engine written in Python. It maps an organization's perimeter and audits defensive configurations purely through **passive intelligence vectors**—harvesting data from DNS infrastructure, public Certificate Transparency logs, and perimeter HTTP responses without launching intrusive scans or direct port probes.

---

## ⚡ Key Capabilities

* **Phase 1: DNS & Infrastructure Telemetry**
  * Resolves authoritative IPv4 addresses (A records) and identifies reverse PTR hostnames.
  * Queries and parses Mail Exchanger (MX) servers alongside DNS priority rankings.
  * Extracts domain verification tokens and anti-spoofing policies (TXT, SPF records).

* **Phase 2: Geo-IP & ASN Footprinting**
  * Identifies target hosting infrastructure, data center locations, and upstream Internet Service Providers (ISPs).
  * Collects Autonomous System Numbers (ASN) and organization ownership metadata.

* **Phase 3: Multi-Threaded Passive Subdomain Discovery**
  * Queries public SSL/TLS Certificate Transparency (CT) logs via crt.sh to uncover indexed subdomains.
  * Uses asynchronous worker threads (ThreadPoolExecutor) to rapidly resolve and filter active hosts.

* **Phase 4: Defensive Posture Auditing & Tech-Stack Fingerprinting**
  * Inspects web server banners (Apache, Nginx, Cloudflare, etc.).
  * Audits essential HTTP security headers against OWASP standards:
    * Strict-Transport-Security (HSTS)
    * Content-Security-Policy (CSP & frame-ancestors)
    * X-Frame-Options (Clickjacking Mitigation)
    * X-Content-Type-Options (MIME Sniffing Mitigation)
    * Referrer-Policy
  * Programmatically calculates a **Defensive Security Score (0–100)** with corresponding posture letter grades (A to F).

* **Machine-Readable Telemetry Export**
  * Formats complete intelligence footprints into structured JSON files (report.json) for pipeline ingestion or incident reporting.

---

## 🛠️ Installation & Setup

```bash
# 1. Clone the repository
git clone [https://github.com/abhayverma-18/AbhayRecon.git](https://github.com/abhayverma-18/AbhayRecon.git)
cd AbhayRecon

# 2. Install required system packages (Kali Linux)
sudo apt update && sudo apt install -y python3-dnspython python3-requests

# Or install via Python package manager
pip install -r requirements.txt

# 3. Grant execution permissions to script
chmod +x abhayrecon.py

🚀 How to Run (Usage)1. Basic Target ReconnaissanceTarget domain audit karne ke liye:Bashpython3 abhayrecon.py -d example.com
2. Export Telemetry to JSON ReportAudit results ko machine-readable JSON format me save karne ke liye:Bashpython3 abhayrecon.py -d example.com -o report.json
3. Command-Line Arguments ReferenceFlagLong FlagDescriptionMandatory-d--domainTarget domain name to audit (e.g. nmap.org, cloudflare.com)Yes-o--outputSave scan report as structured JSON format fileNo-h--helpShow command usage and parameters help menuNo🖥️ Sample Terminal ExecutionPlaintext[*] Target Initialized: cloudflare.com

[+] Phase 1: DNS & Infrastructure Intelligence
  [A Record] 104.16.132.229
  [MX Server] mxa.global.inbound.cf-emailsecurity.net (Priority: 10)

[+] Phase 2: Geo-IP & ASN Footprint
  [Location]     Toronto, Ontario, Canada
  [ISP / ASN]    Cloudflare, Inc. (AS13335 Cloudflare, Inc.)

[+] Phase 3: Passive Subdomain Enumeration (crt.sh)
  [*] Discovered 3424 unique subdomains from transparency logs.
  [✔] Verified 4 / 3424 subdomains as ACTIVE.

[+] Phase 4: Defensive Posture & Tech-Stack Fingerprint
  [Final URL Target] [https://www.cloudflare.com/](https://www.cloudflare.com/)
  [Tech Detected]    Server: cloudflare
  [SECURE]        Strict-Transport-Security
  [SECURE]        Content-Security-Policy
  [SECURE]        X-Frame-Options
  [SECURE]        X-Content-Type-Options
  [SECURE]        Referrer-Policy

  Security Score: 100/100 | Posture Grade: A (Hardened)

[✔] AbhayRecon Execution Finished!
⚖️ Legal & Ethical DisclaimerThis project is developed strictly for educational purposes, security research, and authorized defensive perimeter analysis. Always ensure written authorization before probing infrastructure you do not own.👤 AuthorName: Abhay VermaFocus: Cybersecurity & Digital ForensicsGitHub: @abhayverma-18EOF
