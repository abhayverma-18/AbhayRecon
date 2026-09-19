#!/usr/bin/env python3
"""
AbhayRecon - Advanced Passive Attack Surface Engine
Author: Abhay Verma
Repository: https://github.com/AbhayVerma/AbhayRecon
"""

import sys
import argparse
import socket
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import requests

# ANSI Color Codes
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
    ___  _     _                 ____                      
   / _ \\| |__ | |__   __ _ _   _|  _ \\ ___  ___ ___  _ __  
  / /_\\ \\ '_ \\| '_ \\ / _` | | | | |_) / _ \\/ __/ _ \\| '_ \\ 
 / /_\\\\ \\ |_) | | | | (_| | |_| |  _ <  __/ (_| (_) | | | |
 \\/    \\/_.__/|_| |_|\\__,_|\\__, |_| \\_\\___|\\___\\___/|_| |_|
                           |___/                           
    {YELLOW}[*] Multi-Vector Passive Attack Surface Engine
    {BLUE}[*] Author: Abhay Verma | Version: 1.2.0
    {RESET}"""
    print(banner)


def sanitize_domain(target):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    return domain.split(":")[0].strip("/")


def query_dns_records(domain):
    print(f"\n{BOLD}[+] Phase 1: DNS & Infrastructure Intelligence{RESET}")
    dns_data = {"A": [], "MX": [], "TXT": [], "reverse_dns": {}}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        a_records = resolver.resolve(domain, "A")
        for ip in a_records:
            ip_str = ip.to_text()
            dns_data["A"].append(ip_str)
            print(f"  {GREEN}[A Record]{RESET} {ip_str}")
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
                dns_data["reverse_dns"][ip_str] = hostname
                print(f"      {CYAN}└── PTR Host:{RESET} {hostname}")
            except (socket.herror, socket.gaierror):
                dns_data["reverse_dns"][ip_str] = "No PTR found"
    except Exception:
        print(f"  {RED}[-] Could not resolve A records.{RESET}")

    try:
        mx_records = resolver.resolve(domain, "MX")
        for mx in mx_records:
            exchange = mx.exchange.to_text().strip(".")
            dns_data["MX"].append(exchange)
            print(f"  {BLUE}[MX Server]{RESET} {exchange} (Priority: {mx.preference})")
    except Exception:
        pass

    try:
        txt_records = resolver.resolve(domain, "TXT")
        for txt in txt_records:
            raw_text = txt.to_text().strip('"')
            dns_data["TXT"].append(raw_text)
            display_txt = raw_text if len(raw_text) < 70 else raw_text[:67] + "..."
            print(f"  {YELLOW}[TXT Record]{RESET} {display_txt}")
    except Exception:
        pass

    return dns_data


def get_geoip_intelligence(ip_address):
    print(f"\n{BOLD}[+] Phase 2: Geo-IP & ASN Footprint{RESET}")
    geo_data = {}
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,isp,org,as,query"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo_data = {
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "city": f"{data.get('city')}, {data.get('regionName')}",
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("as"),
                }
                print(f"  {CYAN}[Location]{RESET}     {geo_data['city']}, {geo_data['country']}")
                print(f"  {CYAN}[ISP / ASN]{RESET}    {geo_data['isp']} ({geo_data['asn']})")
                print(f"  {CYAN}[Organization]{RESET} {geo_data['organization']}")
                return geo_data
    except Exception:
        pass

    print(f"  {YELLOW}[!] Could not resolve Geo-IP metadata.{RESET}")
    return geo_data


def check_subdomain_alive(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return subdomain, True
    except (socket.gaierror, socket.herror):
        return subdomain, False


def discover_subdomains(domain):
    print(f"\n{BOLD}[+] Phase 3: Passive Subdomain Enumeration (crt.sh){RESET}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    extracted = set()

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                val = item.get("name_value", "")
                for sub in val.split("\n"):
                    sub_clean = sub.strip().lower()
                    if sub_clean and not sub_clean.startswith("*.") and sub_clean.endswith(domain):
                        extracted.add(sub_clean)
    except Exception:
        pass

    total_found = len(extracted)
    print(f"  {CYAN}[*] Discovered {total_found} unique subdomains from transparency logs.{RESET}")

    live_subdomains = []
    if total_found > 0:
        print(f"  {CYAN}[*] Running multi-threaded DNS probes to verify active targets...{RESET}")
        with ThreadPoolExecutor(max_workers=15) as executor:
            results = executor.map(check_subdomain_alive, sorted(list(extracted)))
            for sub, is_alive in results:
                if is_alive:
                    live_subdomains.append(sub)
                    if len(live_subdomains) <= 8:
                        print(f"      {GREEN}[ALIVE]{RESET} {sub}")

        if len(live_subdomains) > 8:
            print(f"      {YELLOW}...and {len(live_subdomains) - 8} more live subdomains verified!{RESET}")

    print(f"  {GREEN}[✔] Verified {len(live_subdomains)} / {total_found} subdomains as ACTIVE.{RESET}")
    return {"total": total_found, "live": live_subdomains}


def audit_security_and_tech(domain):
    print(f"\n{BOLD}[+] Phase 4: Defensive Posture & Tech-Stack Fingerprint{RESET}")
    target_url = f"https://{domain}"
    header_results = {}
    tech_detected = {}
    score = 100

    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        session = requests.Session()
        resp = session.get(target_url, headers=browser_headers, timeout=10, allow_redirects=True)
        resp_headers = resp.headers

        # Final destination check in case of redirects (e.g. tesla.com -> www.tesla.com)
        if resp.url:
            print(f"  {CYAN}[Final URL Target]{RESET} {resp.url}")

        fingerprint_keys = ["Server", "X-Powered-By", "X-AspNet-Version", "Via"]
        for key in fingerprint_keys:
            if key in resp_headers:
                tech_detected[key] = resp_headers[key]
                print(f"  {BLUE}[Tech Detected]{RESET}    {key}: {resp_headers[key]}")

        # Header definitions and checks
        hsts = "Strict-Transport-Security" in resp_headers
        csp = "Content-Security-Policy" in resp_headers
        csp_val = resp_headers.get("Content-Security-Policy", "")
        frame_options = "X-Frame-Options" in resp_headers
        content_type = "X-Content-Type-Options" in resp_headers
        referrer = "Referrer-Policy" in resp_headers
        permissions = "Permissions-Policy" in resp_headers

        # Strict-Transport-Security (25 pts)
        if hsts:
            print(f"  {GREEN}[SECURE]{RESET}        Strict-Transport-Security")
            header_results["Strict-Transport-Security"] = {"status": "Present", "value": resp_headers["Strict-Transport-Security"]}
        else:
            score -= 25
            print(f"  {RED}[EXPOSED]{RESET}       Strict-Transport-Security is missing!")
            header_results["Strict-Transport-Security"] = {"status": "Missing", "value": None}

        # Content-Security-Policy (30 pts)
        if csp:
            print(f"  {GREEN}[SECURE]{RESET}        Content-Security-Policy")
            header_results["Content-Security-Policy"] = {"status": "Present", "value": csp_val[:60] + "..." if len(csp_val) > 60 else csp_val}
        else:
            score -= 30
            print(f"  {RED}[EXPOSED]{RESET}       Content-Security-Policy is missing!")
            header_results["Content-Security-Policy"] = {"status": "Missing", "value": None}

        # Clickjacking Defense (20 pts): Frame-Options OR CSP frame-ancestors
        if frame_options:
            print(f"  {GREEN}[SECURE]{RESET}        X-Frame-Options")
            header_results["X-Frame-Options"] = {"status": "Present", "value": resp_headers["X-Frame-Options"]}
        elif csp and "frame-ancestors" in csp_val:
            print(f"  {GREEN}[SECURE]{RESET}        Clickjacking Protected (via CSP frame-ancestors)")
            header_results["X-Frame-Options"] = {"status": "Handled via CSP frame-ancestors", "value": "frame-ancestors"}
        else:
            score -= 20
            print(f"  {RED}[EXPOSED]{RESET}       X-Frame-Options / frame-ancestors is missing!")
            header_results["X-Frame-Options"] = {"status": "Missing", "value": None}

        # MIME Sniffing Defense (15 pts)
        if content_type:
            print(f"  {GREEN}[SECURE]{RESET}        X-Content-Type-Options")
            header_results["X-Content-Type-Options"] = {"status": "Present", "value": resp_headers["X-Content-Type-Options"]}
        else:
            score -= 15
            print(f"  {RED}[EXPOSED]{RESET}       X-Content-Type-Options is missing!")
            header_results["X-Content-Type-Options"] = {"status": "Missing", "value": None}

        # Referrer Policy (10 pts)
        if referrer:
            print(f"  {GREEN}[SECURE]{RESET}        Referrer-Policy")
            header_results["Referrer-Policy"] = {"status": "Present", "value": resp_headers["Referrer-Policy"]}
        else:
            score -= 10
            print(f"  {RED}[EXPOSED]{RESET}       Referrer-Policy is missing!")
            header_results["Referrer-Policy"] = {"status": "Missing", "value": None}

    except requests.exceptions.RequestException as e:
        print(f"  {RED}[-] Could not reach target over HTTPS: {e}{RESET}")
        score = 0

    if score >= 85:
        grade = f"{GREEN}A (Hardened){RESET}"
    elif score >= 65:
        grade = f"{YELLOW}B (Moderate){RESET}"
    elif score >= 45:
        grade = f"{YELLOW}C (Weak){RESET}"
    else:
        grade = f"{RED}F (Critical Gaps){RESET}"

    print(f"\n  {BOLD}Security Score: {score}/100 | Posture Grade: {grade}")
    return {"score": score, "headers": header_results, "tech_fingerprint": tech_detected}


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="AbhayRecon: Passive Attack Surface & Threat Recon Engine"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Save reconnaissance report to JSON file")

    args = parser.parse_args()
    clean_target = sanitize_domain(args.domain)

    print(f"{GREEN}[*] Target Initialized:{RESET} {BOLD}{clean_target}{RESET}")

    dns_intel = query_dns_records(clean_target)

    geo_intel = {}
    if dns_intel["A"]:
        primary_ip = dns_intel["A"][0]
        geo_intel = get_geoip_intelligence(primary_ip)

    sub_intel = discover_subdomains(clean_target)
    posture_intel = audit_security_and_tech(clean_target)

    if args.output:
        full_report = {
            "target": clean_target,
            "dns_intelligence": dns_intel,
            "geo_ip_footprint": geo_intel,
            "subdomain_intelligence": sub_intel,
            "security_posture": posture_intel,
        }
        with open(args.output, "w") as f:
            json.dump(full_report, f, indent=4)
        print(f"\n{GREEN}{BOLD}[✔] Intelligence report successfully exported to: {args.output}{RESET}")

    print(f"\n{GREEN}{BOLD}[✔] AbhayRecon Execution Finished!{RESET}\n")


if __name__ == "__main__":
    main()
