# siem_integration/splunk_forwarder.py
# Gatekeeper 2: Operation Echelon
# Splunk HEC Forwarder

import requests
import datetime
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Config — update HEC_TOKEN after Splunk setup on VM3
HEC_URL = "https://192.168.56.104:8088/services/collector"
HEC_TOKEN = "622b28d0-3013-46e2-8da2-8958223eda9d"


def send_event(event_data, sourcetype="echelon_event"):
    """Send a single event to Splunk HEC"""
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "time": datetime.datetime.utcnow().timestamp(),
        "host": "gatekeeper2-echelon",
        "source": "operation_echelon",
        "sourcetype": sourcetype,
        "event": event_data
    }
    try:
        resp = requests.post(
            HEC_URL, json=payload,
            headers=headers, verify=False, timeout=5)
        if resp.status_code == 200:
            print(f"[+] Event sent to Splunk: {sourcetype}")
        else:
            print(f"[-] Splunk HEC error: {resp.status_code} — {resp.text}")
        return resp
    except requests.exceptions.ConnectionError:
        print("[-] Splunk not reachable — is VM3 running?")
        return None


def send_ioc_event(ioc):
    """Send IOC extraction event to Splunk"""
    event = {
        "event_type": "IOC_DETECTED",
        "threat_actor": ioc.get("source", "unknown"),
        "attacker_ip": ioc.get("attacker_ip"),
        "threat_type": ioc.get("threat_type"),
        "target": ioc.get("target"),
        "confidence": ioc.get("confidence"),
        "slice_target": ioc.get("slice_target"),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    return send_event(event, sourcetype="threat_intel")


def send_anomaly_event(src_ip, bytes_orig, pkts_orig, score):
    """Send AI anomaly detection event to Splunk"""
    event = {
        "event_type": "AI_ANOMALY_DETECTED",
        "src_ip": src_ip,
        "bytes_orig": bytes_orig,
        "pkts_orig": pkts_orig,
        "anomaly_score": score,
        "detection_method": "IsolationForest",
        "confidence": "ANOMALOUS",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    return send_event(event, sourcetype="ai_anomaly_detection")


def send_soar_event(ip, action, method="iptables"):
    """Send SOAR response action to Splunk"""
    event = {
        "event_type": f"SOAR_{action}",
        "ip": ip,
        "action": action,
        "method": method,
        "automated": True,
        "operator": "echelon-soar",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    return send_event(event, sourcetype="soar_response")


def test_connection():
    """Test HEC connectivity"""
    print(f"[*] Testing Splunk HEC at {HEC_URL}...")
    result = send_event(
        {"test": "Gatekeeper 2 HEC connectivity check",
         "status": "online"},
        sourcetype="echelon_test")
    if result and result.status_code == 200:
        print("[+] Splunk HEC connection successful")
        return True
    return False


if __name__ == "__main__":
    test_connection()
