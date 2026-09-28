# Operation Echelon — ITIL Incident Response Mapping

**Incident Reference:** INC-ECH-001  
**Classification:** Critical — DDoS simulation within the 5G lab environment  
**Threat Actor:** `null_meridian` *(fictional)*  
**Attack Vector:** SYN flood + UDP flood targeting TCP/80 and the GTP-U service port (UDP/2152)  
**Target:** Helix-Pulse 5G Core (`192.168.56.102`)  
**Linked Project:** Project Gatekeeper — Identity Security Layer  

---

## Background

Following Helix Communications' acquisition of Pulse, a fictional regional 5G operator serving 340,000 subscribers across Northern England and the Midlands, the scenario introduces a 72-hour security exposure window before full integration of the acquired infrastructure.

On Day 31 post-announcement, simulated dark-web threat intelligence attributed to the fictional threat actor `null_meridian` indicated a commissioned DDoS campaign with the enterprise URLLC (Ultra-Reliable Low-Latency Communications) slice identified as the intended target.

The lab traffic simulation subsequently generated:

- A SYN flood targeting TCP port `80`
- A UDP flood targeting port `2152`, the standard GTP-U service port

The UDP simulation targeted the GTP-U service port but did not emulate complete GTP-U protocol traffic or a real carrier network attack.

This document maps the incident lifecycle through ITIL 4 incident-management stages, from simulated threat intelligence through detection, automated mitigation, recovery, and review, as demonstrated within the isolated Operation Echelon lab environment.

---

## ITIL Stage Mapping

| Stage | Activity | Tool | Evidence |
|---|---|---|---|
| **Event Detection** | Simulated dark-web post surfaces from `null_meridian` | Python IOC extractor (`ioc_extractor.py`) | `darkweb_data.json` ingested; 3 IOCs extracted |
| **Incident Logging** | IOC data structured and ingested into the SIEM | SQLite blacklist + Splunk HEC | `sourcetype=threat_intel`; 3 events visible in Splunk |
| **Classification** | Threats classified by confidence and scenario target | `blacklist_db.py` | HIGH (URLLC), MEDIUM (eMBB), LOW (mMTC) |
| **Investigation** | Network detections reviewed alongside Isolation Forest anomaly results | Zeek + Isolation Forest (`anomaly_detector.py`) | `DDoS_GTP_Flood` and `DDoS_SYN_Flood` notices; 20 anomaly events sent to Splunk |
| **Response** | Automated responder blocks qualifying IOCs | `auto_responder.py --mode respond` | `SOAR_BLOCK_EXECUTED` events; `iptables` DROP rules applied |
| **Recovery** | Blocked IPs removed after the simulated threat is cleared | `auto_responder.py --mode recover` | `SOAR_RECOVERY_COMPLETE`; `iptables` rules removed |
| **Review** | Incident timeline reconstructed from correlated telemetry | Splunk correlation search | IOC → detection → response events visible in a single query |

---

## RACI Matrix

| Activity | SOC Analyst | CISO | Network Engineer | Automation (SOAR) |
|---|---|---|---|---|
| Dark-web monitoring | R | I | — | A |
| IOC extraction | R, A | I | — | — |
| SIEM alert triage | R | I | — | A |
| Incident classification | R, A | C | — | — |
| Attack detection (Isolation Forest / Zeek) | — | I | C | R, A |
| IP block execution | — | A | R | R |
| Slice QoS protection | — | A | R | — |
| Service recovery | R | A | C | R |
| Post-incident review | R | A | C | — |

**R** = Responsible · **A** = Accountable · **C** = Consulted · **I** = Informed

---

## Key Metrics

| Metric | Definition | Result |
|---|---|---|
| **Automated Mitigation Execution Time** | Responder invocation → `iptables` rule application | **1.084 seconds** |
| **IOCs Extracted** | Total simulated threat-intelligence IOCs processed | **3** |
| **IOCs Auto-Blocked** | HIGH + MEDIUM confidence IOCs blocked | **2** |
| **IOCs Skipped (Manual Review)** | LOW confidence IOCs requiring analyst judgment | **1** |
| **Isolation Forest Anomalies Flagged** | Connections flagged by the experimental anomaly-detection model | **20 of 323,402 scored** |
| **Zeek Detection Types** | Custom notices generated during the simulations | `DDoS_SYN_Flood`, `DDoS_GTP_Flood` |
| **UDP/2152 Simulation** | UDP flood directed at the standard GTP-U service port | **UDP/2152** |
| **Network Slices** | Lab-configured slices with QoS implemented using Linux `tc` | **3 — eMBB, URLLC, mMTC** |

---

## Note on the Isolation Forest Baseline

The Isolation Forest model was trained on a short baseline capture containing only **7 records** during this lab run.

This limited the model's ability to establish a representative normal-traffic profile and cleanly distinguish the simulated attacker from other anomalous connections.

The attacker IP (`192.168.56.105`) was included among the **20 connections flagged as anomalous**, but the model did not uniquely isolate it from the other results.

For this reason, the Isolation Forest component is treated as an **experimental supporting signal rather than an authoritative detection source**.

A longer and more representative baseline would be required to properly evaluate the model's detection performance.

---

## MITRE ATT&CK Mapping

| Technique | ID | Lab Mapping |
|---|---|---|
| **Network Denial of Service: Direct Network Flood** | T1498.001 | SYN and UDP flood simulations against the lab 5G-core host |


> **Scope note:** The UDP simulation targeted port `2152`, commonly used by GTP-U. It did not construct full GTP-U protocol traffic or reproduce a carrier-grade GTP-U attack.

---

## Incident Timeline — Actual Lab Timestamps

```text
T+0:00:00   Simulated null_meridian dark-web post ingested

T+0:00:02   IOC extraction complete
            3 IOCs written to blacklist

T+0:00:04   IOC events visible in Splunk
            sourcetype=threat_intel

T+0:05:00   Traffic simulation launched from VM4
            SYN flood targeting TCP/80
            UDP flood targeting UDP/2152

T+0:05:08   Zeek raises DDoS_SYN_Flood notice

T+0:05:11   Zeek raises DDoS_GTP_Flood notice
            UDP/2152-targeted detection

T+0:06:30   Isolation Forest executed
            20 anomalies flagged
            attacker IP 192.168.56.105 included among results

T+0:06:32   Anomaly events sent to Splunk
            sourcetype=ai_anomaly_detection

T+0:08:00   auto_responder.py invoked

T+0:08:01   iptables DROP rules applied
            Automated mitigation execution time: 1.084 seconds

T+0:08:01   SOAR_BLOCK_EXECUTED logged to Splunk

T+0:10:00   Simulated threat cleared
            Recovery initiated

T+0:10:02   iptables rules removed

T+0:10:02   SOAR_RECOVERY_COMPLETE logged to Splunk
```

---

## Full Incident Timeline in Splunk

The incident lifecycle was reconstructed using a Splunk correlation query:

```spl
index=* (
    sourcetype=threat_intel OR
    sourcetype=ai_anomaly_detection OR
    sourcetype=soar_response
)
| eval stage=case(
    sourcetype=="threat_intel", "1_IOC_DETECTED",
    sourcetype=="ai_anomaly_detection", "2_ANOMALY_FLAGGED",
    sourcetype=="soar_response", "3_RESPONSE_TAKEN"
)
| table _time, stage, sourcetype, attacker_ip,
        src_ip, ip, action, confidence
| sort _time
```

### Stages Visible in Splunk

| Stage | Sourcetype | IPs | Count |
|---|---|---|---:|
| `1_IOC_DETECTED` | `threat_intel` | `192.168.56.105`, `192.168.56.110`, `192.168.56.111` | 3 |
| `2_ATTACK_DETECTED` | `ai_anomaly_detection` | `192.168.56.105`, `192.168.56.1`, `192.168.56.102`, `192.168.56.104` | 20 |
| `3_RESPONSE_TAKEN` | `soar_response` | `192.168.56.105`, `192.168.56.110` | 9+ |

---

## Conclusion

Operation Echelon demonstrates a lab-based security monitoring and response workflow combining:

- Simulated dark-web threat intelligence
- IOC extraction and confidence classification
- Zeek network detection
- Experimental Isolation Forest anomaly detection
- Splunk-based telemetry and incident correlation
- Automated IOC-based containment using `iptables`
- Automated recovery and response logging

The lab intentionally combines these components to explore how threat intelligence, network telemetry, anomaly detection, SIEM visibility, and automated response can operate as parts of a broader security workflow.

The **1.084-second measurement applies specifically to the automated mitigation stage** — from responder invocation to `iptables` rule application — rather than to the complete threat-intelligence-to-containment lifecycle.

### Key Takeaway

Once the automated responder was invoked, the `iptables` mitigation completed in **1.084 seconds**.

In a production environment, this type of automated containment could help reduce response time and limit the operational impact of confirmed threats. Production deployment would require stronger validation, safeguards, approval logic, representative baselines, and integration with the operator's actual network and security controls.

---

## References

- Project Gatekeeper — Identity Security
- MITRE ATT&CK — T1498
- ITIL 4 Incident Management

---

**Author:** Oluwatobi Babalola  
**GitHub:** `@BabsBBG`  
**LinkedIn:** Oluwatobi Babalola
