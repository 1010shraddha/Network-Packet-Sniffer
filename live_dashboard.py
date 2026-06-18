from flask import Flask, render_template
from scapy.all import sniff, TCP, UDP, ICMP, IP, DNSQR
import threading
from collections import Counter

app = Flask(__name__)

# =========================
# Live Statistics
# =========================

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0
}

# =========================
# Live Data
# =========================

source_counter = Counter()
destination_counter = Counter()

dns_queries = []

# =========================
# Packet Processing
# =========================

def packet_callback(packet):

    stats["total"] += 1

    if packet.haslayer(TCP):
        stats["tcp"] += 1

    elif packet.haslayer(UDP):
        stats["udp"] += 1

    elif packet.haslayer(ICMP):
        stats["icmp"] += 1

    # IP Tracking

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        source_counter[src_ip] += 1
        destination_counter[dst_ip] += 1

    # DNS Monitoring

    if packet.haslayer(DNSQR):

        try:

            domain = packet[DNSQR].qname.decode()

            if domain not in dns_queries:

                dns_queries.append(domain)

                if len(dns_queries) > 20:
                    dns_queries.pop(0)

        except:
            pass

# =========================
# Dashboard Route
# =========================

@app.route("/")
def dashboard():

    return render_template(
        "live_dashboard.html",

        stats=stats,

        top_sources=source_counter.most_common(5),

        top_destinations=destination_counter.most_common(5),

        dns_queries=dns_queries,

        tcp=stats["tcp"],
        udp=stats["udp"],
        icmp=stats["icmp"]
    )

# =========================
# Start Sniffer
# =========================

def start_sniffer():

    sniff(
        prn=packet_callback,
        store=False
    )

# =========================
# Main
# =========================

if __name__ == "__main__":

    sniffer_thread = threading.Thread(
        target=start_sniffer
    )

    sniffer_thread.daemon = True
    sniffer_thread.start()

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )