from flask import Flask, render_template
import pandas as pd
import os

app = Flask(__name__)

@app.route("/")
def dashboard():

    df = pd.read_csv("traffic_log.csv")

    total_packets = len(df)

    protocol_stats = (
        df["Protocol"]
        .value_counts()
        .to_dict()
    )

    top_sources = (
        df["Source IP"]
        .value_counts()
        .head(5)
        .to_dict()
    )

    top_destinations = (
        df["Destination IP"]
        .value_counts()
        .head(5)
        .to_dict()
    )

    dns_queries = []

    if os.path.exists("dns_log.txt"):
        with open("dns_log.txt", "r") as f:
            dns_queries = f.readlines()

    return render_template(
        "dashboard.html",
        total_packets=total_packets,
        protocol_stats=protocol_stats,
        top_sources=top_sources,
        top_destinations=top_destinations,
        dns_queries=dns_queries[:10]
    )

if __name__ == "__main__":
    app.run(debug=True)