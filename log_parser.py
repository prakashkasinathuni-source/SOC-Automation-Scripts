# SOC Automation Script - Log Parser
# Purpose: Basic parsing of failed login logs for brute force detection

from collections import Counter

log_file = "sample_logs.txt"

def parse_logs(file):
    failed_ips = []

    with open(file, "r") as f:
        for line in f:
            if "Failed Login" in line:
                parts = line.split()
                ip = parts[-1]
                failed_ips.append(ip)

    return failed_ips


def detect_bruteforce(ips):
    counts = Counter(ips)

    print("\n=== Brute Force Detection Report ===")
    for ip, count in counts.items():
        print(f"{ip} -> {count} attempts")

        if count > 10:
            print("[ALERT] Possible brute force attack detected!")


if __name__ == "__main__":
    ips = parse_logs(log_file)
    detect_bruteforce(ips)
