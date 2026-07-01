# ddos_simulation/influx_writer.py
# Simple InfluxDB writer for Zeek conn.log

import pandas as pd
import datetime
import os
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# ---- CONFIG ----
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "XYC1DrPFcEZFtfrDl7CrW1gOiWQ5dyd3jSxATb-Vp5kLS8J7pVWsE7wexMPjtVA7KdEE3fwwtVcyqCZpLa-vhg=="
INFLUX_ORG = "echelon"
INFLUX_BUCKET = "attack_metrics"

# ---- PARSING ----
def parse_conn_log(log_path):
    """Parse Zeek conn.log into DataFrame"""
    records, fields = [], []
    with open(log_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#fields'):
                fields = line.split('\t')[1:]
                continue
            if line.startswith('#'):
                continue
            values = line.split('\t')
            if len(values) == len(fields):
                records.append(dict(zip(fields, values)))
    return pd.DataFrame(records)

# ---- WRITE ----
def write_connections_to_influx(df):
    """Write each connection as a point"""
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    points = []
    count = 0

    for _, row in df.iterrows():
        # Extract fields (skip missing values)
        try:
            orig_pkts = float(row['orig_pkts']) if row.get('orig_pkts') not in ('-', '') else 0.0
            resp_pkts = float(row['resp_pkts']) if row.get('resp_pkts') not in ('-', '') else 0.0
            orig_bytes = float(row['orig_bytes']) if row.get('orig_bytes') not in ('-', '') else 0.0
            resp_bytes = float(row['resp_bytes']) if row.get('resp_bytes') not in ('-', '') else 0.0
            duration   = float(row['duration']) if row.get('duration') not in ('-', '') else 0.0

            # Only write if there is at least one positive value
            if orig_pkts == 0 and resp_pkts == 0 and orig_bytes == 0 and resp_bytes == 0:
                continue
        except Exception:
            continue

        # Tags
        src_ip = row.get('id.orig_h', 'unknown')
        dst_ip = row.get('id.resp_h', 'unknown')
        proto = row.get('proto', 'unknown')
        conn_state = row.get('conn_state', 'unknown')

        # Timestamp: use Zeek's 'ts' field (seconds since epoch)
        ts_str = row.get('ts', '')
        try:
            ts = float(ts_str)
            time = datetime.datetime.utcfromtimestamp(ts)
        except Exception:
            time = datetime.datetime.utcnow()

        # Build point
        point = Point("connection") \
            .tag("src_ip", src_ip) \
            .tag("dst_ip", dst_ip) \
            .tag("proto", proto) \
            .tag("conn_state", conn_state) \
            .field("orig_pkts", orig_pkts) \
            .field("resp_pkts", resp_pkts) \
            .field("orig_bytes", orig_bytes) \
            .field("resp_bytes", resp_bytes) \
            .field("duration", duration) \
            .time(time)

        points.append(point)
        count += 1

        # Write in batches of 1000 to avoid memory issues
        if len(points) >= 1000:
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=points)
            points = []
            print(f"[*] Written {count} records so far")

    # Write remaining
    if points:
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=points)

    write_api.close()
    client.close()
    print(f"[+] Done. Total records written: {count}")

# ---- MAIN ----
if __name__ == "__main__":
    log_path = os.path.expanduser("~/gatekeeper2-echelon/conn.log")
    if not os.path.exists(log_path):
        print(f"[-] conn.log not found at {log_path}")
        exit(1)

    print(f"[*] Parsing {log_path}...")
    df = parse_conn_log(log_path)
    print(f"[*] Parsed {len(df)} records")

    # Quick preview
    if len(df) > 0:
        print("[*] Sample columns:", df.columns.tolist()[:10])
        print("[*] First record:", df.iloc[0].to_dict())

    write_connections_to_influx(df)
