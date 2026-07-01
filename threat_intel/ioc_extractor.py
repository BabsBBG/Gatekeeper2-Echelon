# threat_intel/ioc_extractor.py
# Gatekeeper 2: Operation Echelon
# IOC Extraction Engine

import json
import datetime
import os
import sys


def load_threat_feed(filepath):
    """Load and parse a JSON threat feed file"""
    print(f"[*] Loading threat feed: {filepath}")
    with open(filepath) as f:
        data = json.load(f)
    print(f"[+] Feed loaded successfully")
    return data


def extract_ioc_single(data):
    """
    Extract IOC fields from a single threat entry
    Returns a structured dictionary
    """
    ioc = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "attacker_ip": data.get("attacker_ip"),
        "threat_type": data.get("method"),
        "target": data.get("target"),
        "target_detail": data.get("target_detail", ""),
        "confidence": data.get("confidence", "MEDIUM"),
        "source": f"darkweb:{data.get('threat_actor', 'unknown')}",
        "slice_target": data.get("slice_target", "UNKNOWN"),
        "sst": data.get("sst", 0),
        "threat_actor": data.get("threat_actor"),
        "tags": ["ddos", "5g-threat", "echelon"]
    }
    return ioc


def extract_iocs_batch(feed_list):
    """
    Extract IOCs from a list of threat entries
    Returns a list of structured IOC dictionaries
    """
    iocs = []
    for i, entry in enumerate(feed_list, 1):
        print(f"[*] Processing entry {i}/{len(feed_list)}: "
              f"{entry.get('threat_actor')}")
        ioc = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "attacker_ip": entry.get("attacker_ip"),
            "threat_type": entry.get("method"),
            "target": entry.get("target"),
            "confidence": entry.get("confidence", "MEDIUM"),
            "source": f"darkweb:{entry.get('threat_actor')}",
            "slice_target": entry.get("slice_target", "UNKNOWN"),
            "threat_actor": entry.get("threat_actor")
        }
        iocs.append(ioc)
    return iocs


def run_pipeline():
    """
    Main pipeline function
    Orchestrates the full IOC extraction workflow
    """
    # Move to project root so file paths work correctly
    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)

    # Import DB functions — done here to avoid path issues
    sys.path.insert(0, project_root)
    from threat_intel.blacklist_db import (
        init_db, add_ioc, print_blacklist)

    print("=" * 65)
    print("  GATEKEEPER 2: OPERATION ECHELON")
    print("  Threat Intelligence Pipeline — IOC Extraction Engine")
    print("=" * 65)

    # Step 1 — Initialise the database
    print("\n[PHASE 2.1] Initialising blacklist database...")
    conn = init_db("threat_intel/blacklist.db")

    # Step 2 — Process primary threat (null_meridian)
    print("\n[PHASE 2.2] Processing primary threat feed...")
    primary_data = load_threat_feed(
        "darkweb_simulation/darkweb_data.json")
    primary_ioc = extract_ioc_single(primary_data)

    print(f"\n[+] Primary IOC extracted:")
    print(f"    Threat Actor : {primary_ioc['threat_actor']}")
    print(f"    Attacker IP  : {primary_ioc['attacker_ip']}")
    print(f"    Method       : {primary_ioc['threat_type']}")
    print(f"    Target       : {primary_ioc['target']}")
    print(f"    Slice Target : {primary_ioc['slice_target']}")
    print(f"    Confidence   : {primary_ioc['confidence']}")

    add_ioc(conn,
            ip=primary_ioc["attacker_ip"],
            threat_type=primary_ioc["threat_type"],
            source=primary_ioc["source"],
            confidence=primary_ioc["confidence"],
            slice_target=primary_ioc["slice_target"])

    # Step 3 — Process multi-attacker feed
    print("\n[PHASE 2.3] Processing multi-attacker feed...")
    feed_data = load_threat_feed(
        "darkweb_simulation/multi_attacker_feed.json")
    batch_iocs = extract_iocs_batch(feed_data)

    for ioc in batch_iocs:
        # Skip null_meridian — already added from primary feed
        if ioc["attacker_ip"] == primary_ioc["attacker_ip"]:
            print(f"[~] Skipping duplicate: {ioc['attacker_ip']}")
            continue
        add_ioc(conn,
                ip=ioc["attacker_ip"],
                threat_type=ioc["threat_type"],
                source=ioc["source"],
                confidence=ioc["confidence"],
                slice_target=ioc["slice_target"])

    # Step 4 — Display results
    print("\n[PHASE 2.4] Blacklist database current state:")
    print_blacklist(conn)

    print("[+] Phase 2 complete")
    print("[+] IOCs stored in threat_intel/blacklist.db")
    print("[+] Ready for SIEM ingestion — run Phase 3 pipeline")
    print("=" * 65)


if __name__ == "__main__":
    run_pipeline()# threat_intel/ioc_extractor.py
# Gatekeeper 2: Operation Echelon
# IOC Extraction Engine

import json
import datetime
import os
import sys


def load_threat_feed(filepath):
    """Load and parse a JSON threat feed file"""
    print(f"[*] Loading threat feed: {filepath}")
    with open(filepath) as f:
        data = json.load(f)
    print(f"[+] Feed loaded successfully")
    return data


def extract_ioc_single(data):
    """
    Extract IOC fields from a single threat entry
    Returns a structured dictionary
    """
    ioc = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "attacker_ip": data.get("attacker_ip"),
        "threat_type": data.get("method"),
        "target": data.get("target"),
        "target_detail": data.get("target_detail", ""),
        "confidence": data.get("confidence", "MEDIUM"),
        "source": f"darkweb:{data.get('threat_actor', 'unknown')}",
        "slice_target": data.get("slice_target", "UNKNOWN"),
        "sst": data.get("sst", 0),
        "threat_actor": data.get("threat_actor"),
        "tags": ["ddos", "5g-threat", "echelon"]
    }
    return ioc


def extract_iocs_batch(feed_list):
    """
    Extract IOCs from a list of threat entries
    Returns a list of structured IOC dictionaries
    """
    iocs = []
    for i, entry in enumerate(feed_list, 1):
        print(f"[*] Processing entry {i}/{len(feed_list)}: "
              f"{entry.get('threat_actor')}")
        ioc = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "attacker_ip": entry.get("attacker_ip"),
            "threat_type": entry.get("method"),
            "target": entry.get("target"),
            "confidence": entry.get("confidence", "MEDIUM"),
            "source": f"darkweb:{entry.get('threat_actor')}",
            "slice_target": entry.get("slice_target", "UNKNOWN"),
            "threat_actor": entry.get("threat_actor")
        }
        iocs.append(ioc)
    return iocs


def run_pipeline():
    """
    Main pipeline function
    Orchestrates the full IOC extraction workflow
    """
    # Move to project root so file paths work correctly
    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)

    # Import DB functions — done here to avoid path issues
    sys.path.insert(0, project_root)
    from threat_intel.blacklist_db import (
        init_db, add_ioc, print_blacklist)

    print("=" * 65)
    print("  GATEKEEPER 2: OPERATION ECHELON")
    print("  Threat Intelligence Pipeline — IOC Extraction Engine")
    print("=" * 65)

    # Step 1 — Initialise the database
    print("\n[PHASE 2.1] Initialising blacklist database...")
    conn = init_db("threat_intel/blacklist.db")

    # Step 2 — Process primary threat (null_meridian)
    print("\n[PHASE 2.2] Processing primary threat feed...")
    primary_data = load_threat_feed(
        "darkweb_simulation/darkweb_data.json")
    primary_ioc = extract_ioc_single(primary_data)

    print(f"\n[+] Primary IOC extracted:")
    print(f"    Threat Actor : {primary_ioc['threat_actor']}")
    print(f"    Attacker IP  : {primary_ioc['attacker_ip']}")
    print(f"    Method       : {primary_ioc['threat_type']}")
    print(f"    Target       : {primary_ioc['target']}")
    print(f"    Slice Target : {primary_ioc['slice_target']}")
    print(f"    Confidence   : {primary_ioc['confidence']}")

    add_ioc(conn,
            ip=primary_ioc["attacker_ip"],
            threat_type=primary_ioc["threat_type"],
            source=primary_ioc["source"],
            confidence=primary_ioc["confidence"],
            slice_target=primary_ioc["slice_target"])

    # Step 3 — Process multi-attacker feed
    print("\n[PHASE 2.3] Processing multi-attacker feed...")
    feed_data = load_threat_feed(
        "darkweb_simulation/multi_attacker_feed.json")
    batch_iocs = extract_iocs_batch(feed_data)

    for ioc in batch_iocs:
        # Skip null_meridian — already added from primary feed
        if ioc["attacker_ip"] == primary_ioc["attacker_ip"]:
            print(f"[~] Skipping duplicate: {ioc['attacker_ip']}")
            continue
        add_ioc(conn,
                ip=ioc["attacker_ip"],
                threat_type=ioc["threat_type"],
                source=ioc["source"],
                confidence=ioc["confidence"],
                slice_target=ioc["slice_target"])

    # Step 4 — Display results
    print("\n[PHASE 2.4] Blacklist database current state:")
    print_blacklist(conn)

    print("[+] Phase 2 complete")
    print("[+] IOCs stored in threat_intel/blacklist.db")
    print("[+] Ready for SIEM ingestion — run Phase 3 pipeline")
    print("=" * 65)


if __name__ == "__main__":
    run_pipeline()
