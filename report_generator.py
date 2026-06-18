import pandas as pd
from datetime import datetime
import os

# Create reports folder automatically
os.makedirs("reports", exist_ok=True)

# Read traffic log
df = pd.read_csv("traffic_log.csv")

# Statistics
total_packets = len(df)

protocol_stats = df["Protocol"].value_counts()

top_source_ips = df["Source IP"].value_counts().head(5)

top_destination_ips = df["Destination IP"].value_counts().head(5)

total_traffic = df["Packet Size"].sum()

# DNS Summary
dns_summary = "No DNS queries captured."

if os.path.exists("dns_log.txt"):
    with open("dns_log.txt", "r") as dns_file:
        dns_queries = dns_file.readlines()

    if dns_queries:
        unique_domains = list(set([q.strip() for q in dns_queries]))
        dns_summary = "\n".join(unique_domains[:10])

# Risk Assessment
risk_level = "LOW"

if total_packets > 500:
    risk_level = "MEDIUM"

if total_packets > 1000:
    risk_level = "HIGH"

# Generate Report
report = f"""
==================================================
        NETWORK SECURITY ANALYSIS REPORT
==================================================

Generated On:
{datetime.now()}

--------------------------------------------------
TRAFFIC SUMMARY
--------------------------------------------------

Total Packets Captured : {total_packets}

Total Traffic Volume   : {total_traffic} bytes

Risk Level             : {risk_level}

--------------------------------------------------
PROTOCOL DISTRIBUTION
--------------------------------------------------

{protocol_stats}

--------------------------------------------------
TOP SOURCE IP ADDRESSES
--------------------------------------------------

{top_source_ips}

--------------------------------------------------
TOP DESTINATION IP ADDRESSES
--------------------------------------------------

{top_destination_ips}

--------------------------------------------------
DNS ACTIVITY
--------------------------------------------------

{dns_summary}

--------------------------------------------------
SECURITY OBSERVATIONS
--------------------------------------------------

1. Network traffic was successfully captured.
2. Traffic patterns were analyzed.
3. DNS activity was monitored.
4. Top communicating hosts were identified.
5. Protocol usage statistics were generated.

--------------------------------------------------
RECOMMENDATIONS
--------------------------------------------------

- Continue monitoring network activity.
- Investigate unknown external IPs.
- Monitor suspicious ports.
- Review DNS requests periodically.
- Maintain updated security controls.

==================================================
                 END OF REPORT
==================================================
"""

# Save Report
report_path = os.path.join("reports", "security_report.txt")

with open(report_path, "w", encoding="utf-8") as file:
    file.write(report)

print("Security report generated successfully!")
print(f"Saved to: {report_path}")