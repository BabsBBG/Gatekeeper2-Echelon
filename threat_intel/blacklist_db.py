# threat_intel/blacklist_db.py
# Gatekeeper 2: Operation Echelon
# IOC Blacklist Database

import sqlite3
import datetime


def init_db(path="threat_intel/blacklist.db"):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            ip           TEXT PRIMARY KEY,
            threat_type  TEXT,
            source       TEXT,
            confidence   TEXT,
            added_at     TEXT,
            status       TEXT DEFAULT 'ACTIVE',
            block_count  INTEGER DEFAULT 1,
            slice_target TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ioc_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            event_type  TEXT,
            timestamp   TEXT,
            details     TEXT
        )
    """)
    conn.commit()
    print("[+] Blacklist DB initialised")
    return conn


def add_ioc(conn, ip, threat_type, source,
            confidence="HIGH", slice_target="UNKNOWN"):
    now = datetime.datetime.utcnow().isoformat()
    conn.execute("""
        INSERT INTO blacklist
            (ip, threat_type, source, confidence,
             added_at, slice_target)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            block_count = block_count + 1,
            status = 'ACTIVE',
            confidence = excluded.confidence
    """, (ip, threat_type, source, confidence, now, slice_target))
    conn.execute("""
        INSERT INTO ioc_events
            (ip, event_type, timestamp, details)
        VALUES (?,?,?,?)
    """, (ip, "IOC_ADDED", now,
          f"Source: {source} | Method: {threat_type}"))
    conn.commit()
    print(f"[+] IOC added: {ip} ({threat_type}) "
          f"confidence: {confidence}")


def get_active_blacklist(conn):
    rows = conn.execute(
        "SELECT ip, threat_type, confidence, slice_target "
        "FROM blacklist WHERE status='ACTIVE'"
    ).fetchall()
    return rows


def update_status(conn, ip, status):
    now = datetime.datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE blacklist SET status=? WHERE ip=?", (status, ip))
    conn.execute("""
        INSERT INTO ioc_events
            (ip, event_type, timestamp, details)
        VALUES (?,?,?,?)
    """, (ip, f"STATUS_{status}", now,
          f"Status updated to {status}"))
    conn.commit()
    print(f"[+] {ip} status updated to {status}")


def print_blacklist(conn):
    rows = get_active_blacklist(conn)
    print("\n=== ACTIVE IOC BLACKLIST ===")
    print(f"{'IP':<22} {'THREAT':<28} "
          f"{'CONFIDENCE':<12} {'SLICE'}")
    print("-" * 75)
    for row in rows:
        print(f"{row[0]:<22} {row[1]:<28} "
              f"{row[2]:<12} {row[3]}")
    print(f"\nTotal active IOCs: {len(rows)}\n")


if __name__ == "__main__":
    conn = init_db()
    print_blacklist(conn)
