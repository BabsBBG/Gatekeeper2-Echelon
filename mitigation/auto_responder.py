# mitigation/auto_responder.py
# Gatekeeper 2: Operation Echelon
# SOAR Auto-Responder — Automated DDoS Mitigation

import subprocess
import datetime
import json
import os
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL   = "https://192.168.56.104:8088/services/collector"
HEC_TOKEN = "622b28d0-3013-46e2-8da2-8958223eda9d"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def send_to_splunk(event_data, sourcetype="soar_response"):
    """Log SOAR action to Splunk HEC"""
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type":  "application/json"
    }
    payload = {
        "time":       datetime.datetime.utcnow().timestamp(),
        "host":       "open5gs-core",
        "source":     "echelon-soar",
        "sourcetype": sourcetype,
        "event":      event_data
    }
    try:
        r = requests.post(
            HEC_URL, json=payload,
            headers=headers, verify=False, timeout=5)
        if r.status_code == 200:
            print(f"[+] Splunk logged: {event_data.get('event_type')}")
            return True
        print(f"[-] Splunk error {r.status_code}: {r.text}")
        return False
    except Exception as e:
        print(f"[-] Splunk unreachable: {e}")
        return False


def is_blocked(ip):
    """Check if IP already has a DROP rule in iptables"""
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True)
    return ip in result.stdout


def block_ip(ip, reason="DDoS detected"):
    """Apply iptables DROP rule and log the action"""
    t_start = datetime.datetime.utcnow()
    print(f"\n[SOAR] Blocking: {ip}")
    print(f"[SOAR] Reason  : {reason}")

    if is_blocked(ip):
        print(f"[~] Already blocked: {ip}")
        return True

    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT",
         "-s", ip, "-j", "DROP"],
        capture_output=True, text=True)

    t_end    = datetime.datetime.utcnow()
    mttr     = (t_end - t_start).total_seconds()

    if result.returncode == 0:
        print(f"[+] Blocked: {ip}")
        print(f"[+] MTTR   : {mttr:.3f} seconds")

        send_to_splunk({
            "event_type":           "SOAR_BLOCK_EXECUTED",
            "ip":                   ip,
            "action":               "BLOCKED",
            "method":               "iptables_DROP",
            "reason":               reason,
            "mttr_seconds":         mttr,
            "timestamp":            t_end.isoformat(),
            "automated":            True,
            "operator":             "echelon-soar",
            "itil_stage":           "Response"
        })

        # Update blacklist DB
        _update_db(ip, "BLOCKED")
        return True

    print(f"[-] Block failed: {result.stderr}")
    send_to_splunk({
        "event_type": "SOAR_BLOCK_FAILED",
        "ip": ip,
        "error": result.stderr,
        "timestamp": t_end.isoformat()
    })
    return False


def unblock_ip(ip, reason="Threat cleared"):
    """Remove iptables DROP rule — service recovery"""
    print(f"\n[SOAR] Unblocking: {ip}")

    if not is_blocked(ip):
        print(f"[~] Not currently blocked: {ip}")
        return True

    result = subprocess.run(
        ["sudo", "iptables", "-D", "INPUT",
         "-s", ip, "-j", "DROP"],
        capture_output=True, text=True)

    t_end = datetime.datetime.utcnow()

    if result.returncode == 0:
        print(f"[+] Unblocked: {ip}")

        send_to_splunk({
            "event_type": "SOAR_UNBLOCK_EXECUTED",
            "ip":         ip,
            "action":     "UNBLOCKED",
            "reason":     reason,
            "timestamp":  t_end.isoformat(),
            "automated":  True,
            "itil_stage": "Recovery"
        })

        _update_db(ip, "CLEARED")
        return True

    print(f"[-] Unblock failed: {result.stderr}")
    return False


def _update_db(ip, status):
    """Update IOC status in SQLite blacklist"""
    os.chdir(PROJECT_ROOT)
    try:
        from threat_intel.blacklist_db import init_db, update_status
        conn = init_db("threat_intel/blacklist.db")
        update_status(conn, ip, status)
        conn.close()
    except Exception as e:
        print(f"[-] DB update failed: {e}")


def show_iptables():
    """Display current iptables INPUT rules"""
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT",
         "-n", "-v", "--line-numbers"],
        capture_output=True, text=True)
    print("\n=== IPTABLES INPUT CHAIN ===")
    print(result.stdout)


def run_response():
    """
    Full automated response cycle.
    Reads blacklist, blocks HIGH + MEDIUM confidence IOCs.
    """
    print("=" * 65)
    print("  GATEKEEPER 2: OPERATION ECHELON")
    print("  SOAR Auto-Responder — Automated Mitigation")
    print("=" * 65)

    t_start = datetime.datetime.utcnow()
    print(f"\n[SOAR] Initiated : {t_start.isoformat()}")
    print(f"[SOAR] ITIL Stage : Incident Response")

    send_to_splunk({
        "event_type": "SOAR_RESPONSE_INITIATED",
        "timestamp":  t_start.isoformat(),
        "itil_stage": "Response"
    })

    # Load blacklist
    os.chdir(PROJECT_ROOT)
    from threat_intel.blacklist_db import init_db, get_active_blacklist
    conn    = init_db("threat_intel/blacklist.db")
    iocs    = get_active_blacklist(conn)

    print(f"\n[SOAR] Active IOCs: {len(iocs)}")

    blocked = []
    failed  = []
    skipped = []

    for ioc in iocs:
        ip, threat_type, confidence, slice_target = ioc

        if confidence in ("HIGH", "MEDIUM"):
            ok = block_ip(
                ip,
                reason=f"{threat_type} targeting {slice_target} slice")
            (blocked if ok else failed).append(ip)
        else:
            print(f"[~] Skipped (LOW confidence): {ip}")
            skipped.append(ip)

    t_end  = datetime.datetime.utcnow()
    mttr   = (t_end - t_start).total_seconds()

    print(f"\n=== SOAR RESPONSE SUMMARY ===")
    print(f"Blocked  : {len(blocked)} — {blocked}")
    print(f"Failed   : {len(failed)}")
    print(f"Skipped  : {len(skipped)} (LOW confidence — manual review)")
    print(f"MTTR     : {mttr:.3f} seconds")
    print(f"Complete : {t_end.isoformat()}")

    send_to_splunk({
        "event_type":   "SOAR_RESPONSE_COMPLETE",
        "ips_blocked":  blocked,
        "ips_failed":   failed,
        "ips_skipped":  skipped,
        "mttr_seconds": mttr,
        "timestamp":    t_end.isoformat(),
        "itil_stage":   "Response",
        "automated":    True
    })

    show_iptables()
    print("\n[+] Response complete")
    print("=" * 65)
    return blocked, mttr


def run_recovery():
    """Unblock all IOCs — service restoration."""
    print("=" * 65)
    print("  GATEKEEPER 2: OPERATION ECHELON")
    print("  SOAR Recovery — Service Restoration")
    print("=" * 65)

    t_start = datetime.datetime.utcnow()
    send_to_splunk({
        "event_type": "SOAR_RECOVERY_INITIATED",
        "timestamp":  t_start.isoformat(),
        "itil_stage": "Recovery"
    })

    os.chdir(PROJECT_ROOT)
    from threat_intel.blacklist_db import init_db, get_active_blacklist
    conn       = init_db("threat_intel/blacklist.db")
    iocs       = get_active_blacklist(conn)
    unblocked  = []

    for ioc in iocs:
        ip = ioc[0]
        if unblock_ip(ip, "Post-incident recovery"):
            unblocked.append(ip)

    t_end = datetime.datetime.utcnow()
    print(f"\n=== RECOVERY SUMMARY ===")
    print(f"Unblocked: {len(unblocked)} — {unblocked}")
    print(f"Timestamp: {t_end.isoformat()}")

    send_to_splunk({
        "event_type":    "SOAR_RECOVERY_COMPLETE",
        "ips_unblocked": unblocked,
        "timestamp":     t_end.isoformat(),
        "itil_stage":    "Recovery"
    })

    show_iptables()
    print("[+] Recovery complete — services restored")
    print("=" * 65)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="Gatekeeper 2 SOAR Auto-Responder")
    ap.add_argument(
        "--mode",
        choices=["respond", "recover", "list"],
        default="respond",
        help="respond=block, recover=unblock, list=show rules")
    args = ap.parse_args()

    if args.mode == "respond":
        run_response()
    elif args.mode == "recover":
        run_recovery()
    elif args.mode == "list":
        show_iptables()
