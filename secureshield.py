import requests
import socket
import ssl
import json
import csv
import os

from datetime import datetime

def check_ssl(hostname, findings):

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443), timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                certificate = secure_sock.getpeercert()

                expiry = certificate["notAfter"]

                expiry_date = datetime.strptime(
                    expiry,
                    "%b %d %H:%M:%S %Y %Z"
                )

                print("\n===== SSL/TLS Check =====")
                print("Certificate Expiry:", expiry_date)

                if expiry_date < datetime.now():

                    print("[-] Certificate: EXPIRED")

                    findings.append({
                        "name": "Expired SSL/TLS Certificate",
                        "severity": "High",
                        "description": "The SSL/TLS certificate has expired.",
                        "recommendation": "Renew the SSL/TLS certificate.",
                        "timestamp": datetime.now().isoformat()
                    })

                else:
                    print("[+] Certificate: VALID")

    except Exception as e:
        print("\nSSL/TLS check skipped:", e)

def scan_ports(ip):
    import nmap

    scanner = nmap.PortScanner()
    ports = "21,22,25,80,443"

    scanner.scan(ip, ports)

    services = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS"
    }

    port_results = {}

    print("\n===== TCP Port Scan =====")

    for port, service in services.items():
        state = scanner[ip]["tcp"][port]["state"]
        port_results[port] = state
        print(f"{port}/tcp  {service:<6} {state}")
    return port_results

def discover_directories(url, findings):
    print("\n===== Directory Discovery =====")

    try:
        with open("wordlist.txt") as file:
            words = file.read().splitlines()

        for word in words:
            target = url.rstrip("/") + "/" + word

            try:
                response = requests.get(target, timeout=5)

                if response.status_code in [200, 301, 302, 403]:
                    print(f"[+] {target} -> {response.status_code}")

                    findings.append({
                        "name": "Discovered Directory: " + word,
                        "severity": "Low",
                        "description": "A publicly responding directory or path was discovered.",
                        "recommendation": "Review whether this directory should be publicly accessible.",
                        "timestamp": datetime.now().isoformat()
                    })

            except requests.RequestException:
                pass

    except FileNotFoundError:
        print("Wordlist not found.")

def check_https_redirect(url, findings):
    print("\n===== HTTP to HTTPS Check =====")

    if url.startswith("https://"):
        http_url = "http://" + url.split("://", 1)[1]

        try:
            response = requests.get(http_url, timeout=5, allow_redirects=False)

            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get("Location", "")

                if location.startswith("https://"):
                    print("[+] HTTP redirects to HTTPS")
                else:
                    print("[-] HTTP does not redirect directly to HTTPS")
            else:
                print("[-] HTTP does not redirect to HTTPS")

                findings.append({
                    "name": "Missing HTTP to HTTPS Redirect",
                    "severity": "Medium",
                    "description": "HTTP does not redirect to HTTPS.",
                    "recommendation": "Configure HTTP to redirect to HTTPS.",
                    "timestamp": datetime.now().isoformat()
                })

        except requests.RequestException:
            print("[-] Could not check HTTP redirect")

url = input("Enter target URL: ")

findings = []

try:
    response = requests.get(url, timeout=10)

    hostname = url.split("//")[-1].split("/")[0]
    ip = socket.gethostbyname(hostname)
    discover_directories(url,findings)
    check_https_redirect(url, findings)
    port_results = scan_ports(ip)

    if url.startswith("https://"):
       check_ssl(hostname, findings)

    print("\n===== SecureShield =====")
    print("Target IP:", ip)
    print("Status Code:", response.status_code)
    print("Server:", response.headers.get("Server"))

    security_headers = {
        "Content-Security-Policy": (
            "Medium",
            "The Content-Security-Policy header is missing.",
            "Configure an appropriate Content-Security-Policy header."
        ),
        "X-Frame-Options": (
            "Medium",
            "The X-Frame-Options header is missing.",
            "Configure X-Frame-Options or an equivalent framing policy."
        ),
        "X-Content-Type-Options": (
            "Low",
            "The X-Content-Type-Options header is missing.",
            "Set X-Content-Type-Options to nosniff."
        ),
        "Strict-Transport-Security": (
            "Medium",
            "The Strict-Transport-Security header is missing.",
            "Configure HSTS for HTTPS deployments."
        )
    }

    print("\n===== Security Headers =====")

    for header, details in security_headers.items():
        severity, description, recommendation = details

        if header in response.headers:
            print("[+] " + header + ": Present")
        else:
            print("[-] " + header + ": Missing")

            findings.append({
                "name": "Missing " + header,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
                "timestamp": datetime.now().isoformat()
            })

    print("\n===== Findings =====")

    for finding in findings:
        print("\nName:", finding["name"])
        print("Severity:", finding["severity"])
        print("Description:", finding["description"])
        print("Recommendation:", finding["recommendation"])
        print("Timestamp:", finding["timestamp"])
        os.makedirs("reports", exist_ok=True)

    with open("reports/scan_report.json", "w") as file:
        json.dump({
        "target_url": url,
        "target_ip": ip,
        "status_code": response.status_code,
        "server": response.headers.get("Server"),
        "ports": port_results,
        "findings": findings
    }, file, indent=4)

    with open("reports/scan_report.csv", "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "name",
                "severity",
                "description",
                "recommendation",
                "timestamp"
            ]
        )
        writer.writeheader()
        writer.writerows(findings)

    print("\nReports generated successfully!")
    print("JSON: reports/scan_report.json")
    print("CSV : reports/scan_report.csv")

except Exception as e:
    print("Error:", e)
