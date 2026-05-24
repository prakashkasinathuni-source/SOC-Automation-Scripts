# SOC Automation Script - IOC Checker
# Purpose: Check if IPs / domains / hashes are malicious using simple threat intelligence sources

import requests

def check_ip(ip):
    print(f"\n[+] Checking IP: {ip}")

    # Example API (you can replace with real TI like VirusTotal later)
    url = f"https://ipapi.co/{ip}/json/"

    try:
        response = requests.get(url)
        data = response.json()

        print("Country:", data.get("country_name"))
        print("City:", data.get("city"))
        print("Org:", data.get("org"))

        if data.get("country_name") in ["Russia", "North Korea"]:
            print("[!] Suspicious IP detected based on location risk")

    except Exception as e:
        print("Error fetching IP data:", e)


def check_domain(domain):
    print(f"\n[+] Checking Domain: {domain}")

    url = f"https://dns.google/resolve?name={domain}&type=A"

    try:
        response = requests.get(url)
        data = response.json()

        if "Answer" in data:
            print("Domain resolves successfully")
        else:
            print("[!] Suspicious or non-resolving domain")
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    print("=== SOC IOC Checker ===")

    ip = input("Enter IP to check: ")
    domain = input("Enter domain to check: ")

    check_ip(ip)
    check_domain(domain)
