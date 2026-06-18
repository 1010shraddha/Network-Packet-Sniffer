from scapy.all import *
from collections import Counter, defaultdict
import csv
from datetime import datetime

# =========================
# Statistics
# =========================
tcp_count = 0
udp_count = 0
icmp_count = 0
alert_count = 0
total_bytes = 0

# =========================
# Counters
# =========================
source_counter = Counter()
destination_counter = Counter()
connection_counter = Counter()

# =========================
# DNS Queries
# =========================
dns_queries = []

# =========================
# Port Scan Detection
# =========================
port_tracker = defaultdict(set)
port_scan_alerted = set()

# =========================
# Suspicious Ports
# =========================
SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP"
}

# =========================
# Create CSV File
# =========================
with open("traffic_log.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Packet Size"
    ])

# =========================
# Packet Processing
# =========================
def packet_callback(packet):

    global tcp_count
    global udp_count
    global icmp_count
    global alert_count
    global total_bytes

    protocol = "Unknown"
    src_port = "-"
    dst_port = "-"

    packet_size = len(packet)
    total_bytes += packet_size

    # =========================
    # TCP
    # =========================
    if packet.haslayer(TCP):

        tcp_count += 1
        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Port Scan Detection
        if packet.haslayer(IP):

            source_ip = packet[IP].src

            port_tracker[source_ip].add(dst_port)

            if (
                len(port_tracker[source_ip]) > 10
                and source_ip not in port_scan_alerted
            ):

                print("\n[PORT SCAN ALERT]")
                print(f"Source IP: {source_ip}")
                print(
                    f"Unique Ports Accessed: "
                    f"{len(port_tracker[source_ip])}"
                )

                alert_count += 1
                port_scan_alerted.add(source_ip)

        # Suspicious Port Detection
        if src_port in SUSPICIOUS_PORTS:

            alert_count += 1

            print(
                f"\n[ALERT] Traffic from "
                f"{SUSPICIOUS_PORTS[src_port]} "
                f"(Port {src_port})"
            )

        if dst_port in SUSPICIOUS_PORTS:

            alert_count += 1

            print(
                f"\n[ALERT] Traffic to "
                f"{SUSPICIOUS_PORTS[dst_port]} "
                f"(Port {dst_port})"
            )

    # =========================
    # UDP
    # =========================
    elif packet.haslayer(UDP):

        udp_count += 1
        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # =========================
    # ICMP
    # =========================
    elif packet.haslayer(ICMP):

        icmp_count += 1
        protocol = "ICMP"

    # =========================
    # DNS Monitoring
    # =========================
    if packet.haslayer(DNSQR):

        try:

            domain = packet[DNSQR].qname.decode()

            dns_queries.append(domain)

            print(f"\n[DNS QUERY] {domain}")

            with open("dns_log.txt", "a") as dns_file:
                dns_file.write(domain + "\n")

        except:
            pass

    # =========================
    # IP Analysis
    # =========================
    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        source_counter[src_ip] += 1
        destination_counter[dst_ip] += 1

        connection = f"{src_ip} -> {dst_ip}"
        connection_counter[connection] += 1

        # Live Packet Display
        print(
            f"[{protocol}] "
            f"{src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port}"
        )

        # CSV Logging
        with open("traffic_log.csv", "a", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                datetime.now(),
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_size
            ])

# =========================
# Start Sniffing
# =========================
print("Capturing packets...\n")

sniff(prn=packet_callback, count=100)

# =========================
# Final Report
# =========================

print("\n===== Traffic Statistics =====")
print(f"TCP Packets  : {tcp_count}")
print(f"UDP Packets  : {udp_count}")
print(f"ICMP Packets : {icmp_count}")

print(f"\nTotal Traffic: {total_bytes} bytes")

print("\n===== Top Source IPs =====")
for ip, count in source_counter.most_common(10):
    print(f"{ip} -> {count} packets")

print("\n===== Top Destination IPs =====")
for ip, count in destination_counter.most_common(10):
    print(f"{ip} -> {count} packets")

print("\n===== Top Connections =====")
for conn, count in connection_counter.most_common(10):
    print(f"{conn} : {count}")

print("\n===== DNS Queries =====")
for domain in set(dns_queries):
    print(domain)

print("\n===== Port Scan Summary =====")

scan_found = False

for ip, ports in port_tracker.items():

    if len(ports) > 10:

        scan_found = True

        print(
            f"{ip} accessed "
            f"{len(ports)} unique ports"
        )

if not scan_found:
    print("No port scanning activity detected.")

print(f"\nTotal Alerts Generated: {alert_count}")

print("\nLogs saved to:")
print("traffic_log.csv")
print("dns_log.txt")