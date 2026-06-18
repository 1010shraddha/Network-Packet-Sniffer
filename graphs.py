# import pandas as pd
# import matplotlib.pyplot as plt

# # Read CSV
# df = pd.read_csv("traffic_log.csv")

# # ==========================
# # Protocol Distribution
# # ==========================

# protocol_counts = df["Protocol"].value_counts()

# plt.figure(figsize=(6,6))
# plt.pie(
#     protocol_counts,
#     labels=protocol_counts.index,
#     autopct="%1.1f%%"
# )

# # plt.title("Protocol Distribution")
# # plt.savefig("protocol_distribution.png")
# # plt.close()

# # ==========================
# # Top Source IPs
# # ==========================

# top_sources = df["Source IP"].value_counts().head(10)

# plt.figure(figsize=(8,5))
# top_sources.plot(kind="bar")

# plt.title("Top Source IPs")
# plt.ylabel("Packet Count")

# # plt.tight_layout()
# # plt.savefig("top_source_ips.png")
# # plt.close()

# # ==========================
# # Top Destination IPs
# # ==========================

# top_destinations = df["Destination IP"].value_counts().head(10)

# plt.figure(figsize=(8,5))
# top_destinations.plot(kind="bar")

# plt.title("Top Destination IPs")
# plt.ylabel("Packet Count")

# # plt.tight_layout()
# # plt.savefig("top_destination_ips.png")
# # plt.close()

# print("Graphs generated successfully!")