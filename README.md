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
  * Resolves authoritative IPv4 addresses (`A` records) and identifies reverse PTR hostnames.
  * Queries and parses Mail Exchanger (`MX`) servers alongside DNS priority rankings.
  * Extracts domain verification tokens and anti-spoofing policies (`TXT`, SPF records).

* **Phase 2: Geo-IP & ASN Footprinting**
  * Identifies target hosting infrastructure, data center locations, and upstream Internet Service Providers (ISPs).
  * Collects Autonomous System Numbers (`ASN`) and organization ownership metadata.

* **Phase 3: Multi-Threaded Passive Subdomain Discovery**
  * Queries public SSL/TLS Certificate Transparency (CT) logs via `crt.sh` to uncover indexed subdomains.
  * Uses asynchronous worker threads (`ThreadPoolExecutor`) to rapidly resolve and filter active hosts.

* **Phase 4: Defensive Posture Auditing & Tech-Stack Fingerprinting**
  * Inspects web server banners (Apache, Nginx, Cloudflare, etc.).
  * Audits essential HTTP security headers against OWASP standards:
    * `Strict-Transport-Security` (HSTS)
    * `Content-Security-Policy` (CSP & frame-ancestors)
    * `X-Frame-Options` (Clickjacking Mitigation)
    * `X-Content-Type-Options` (MIME Sniffing Mitigation)
    * `Referrer-Policy`
  * Programmatically calculates a **Defensive Security Score (0–100)** with corresponding posture letter grades (`A` to `F`).

* **Machine-Readable Telemetry Export**
  * Formats complete intelligence footprints into structured JSON files (`report.json`) for pipeline ingestion or incident reporting.

---

## 🛠️ Installation & Execution

```bash
# 1. Clone the repository
git clone [https://github.com/abhayverma-18/AbhayRecon.git](https://github.com/abhayverma-18/AbhayRecon.git)
cd AbhayRecon

# 2. Install required dependencies
sudo apt update && sudo apt install -y python3-dnspython python3-requests
# Or install via pip:
pip install -r requirements.txt

# 3. Grant execution permissions
chmod +x abhayrecon.py

# 4. View help menu & options
python3 abhayrecon.py -h

# 5. Run basic reconnaissance against a target
python3 abhayrecon.py -d example.com

# 6. Run reconnaissance and export results to JSON
python3 abhayrecon.py -d example.com -o report.json
