# siem_integration/siem_pipeline.py
# Gatekeeper 2: Operation Echelon
# Full SIEM Pipeline — reads blacklist, sends to Splunk

import sys
import os

# Add project root to Python path so we can import blacklist_db
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel.blacklist_db import init_db, get_active_blacklist
from siem_integration.splunk_forwarder import send_ioc_event, test_connection


def run_siem_pipeline():
    print("=" * 60)
    print("GATEKEEPER 2: OPERATION ECHELON")
    print("SIEM Pipeline — Blacklist → Splunk")
    print("=" * 60)

    # Step 1 — Test Splunk connection first
    if not test_connection():
        print("[-] Aborting — Splunk not reachable")
        print("[*] Run this script again once VM3 Splunk is running")
        return

    # Step 2 — Load active IOCs from blacklist
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    conn = init_db("threat_intel/blacklist.db")
    iocs = get_active_blacklist(conn)

    print(f"\n[*] Sending {len(iocs)} IOCs to Splunk...")
    for ioc in iocs:
        event = {
            "attacker_ip": ioc[0],
            "threat_type": ioc[1],
            "confidence": ioc[2],
            "slice_target": ioc[3],
            "source": "blacklist_db",
            "target": "helix-pulse-spectranet.co.uk"
        }
        send_ioc_event(event)

    print(f"\n[+] {len(iocs)} IOC events sent to Splunk")
    print("[+] Check Splunk: sourcetype=threat_intel")


if __name__ == "__main__":
    run_siem_pipeline()
