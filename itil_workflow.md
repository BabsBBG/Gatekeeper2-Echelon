Operation Echelon - ITIL Incident Response Mapping
Incident Reference: INC-ECH-001
Classification: Critical - DDoS targeting URLLC enterprise slice
Threat Actor: null_meridian
Attack Vector: UDP flood + SYN flood (GTP-U port 2152 + TCP port 80)
Target: Helix-Pulse 5G Core (192.168.56.102)
Linked Project: Project Gatekeeper - Identity Security Layer

Background
Following Helix Communications' acquisition of Pulse, a regional 5G operator serving 340,000 subscribers across North England and the Midlands, the SOC team identified a critical 72-hour exposure window. Threat actors monitoring the publicly announced M&A transaction had a clear window to probe and attack the newly absorbed 5G infrastructure before full security integration could be completed.

Day 31 post-announcement: Dark web monitoring surfaced a commissioned DDoS campaign from threat actor null_meridian, specifically targeting the enterprise URLLC (Ultra-Reliable Low-Latency Communications) slice, the network segment carrying local authority contracts, emergency services connectivity, and critical infrastructure telemetry.

This document maps the full incident lifecycle through ITIL 4 incident management stages, from initial threat intelligence through automated remediation and recovery. as demonstrated in the Operation Echelon lab environment.

ITIL Stage Mapping
Stage	Activity	Tool	Evidence
Event Detection	Dark web post surfaces from null_meridian	Python IOC extractor (ioc_extractor.py)	darkweb_data.json ingested; 3 IOCs extracted
Incident Logging	IOC data structured and ingested into SIEM	SQLite blacklist + Splunk HEC	sourcetype=threat_intel; 3 events visible in Splunk
Classification	Threats classified by confidence and target slice	blacklist_db.py	HIGH (URLLC), MEDIUM (eMBB), LOW (mMTC)
Investigation	Attack traffic correlated with AI-flagged anomalies	Zeek + Isolation Forest (anomaly_detector.py)	DDoS_GTP_Flood, DDoS_SYN_Flood notices; 20 AI anomaly events sent to Splunk
Response	SOAR engine automatically blocks attacker IPs	auto_responder.py --mode respond	SOAR_BLOCK_EXECUTED events; iptables DROP rules applied
Recovery	Blocked IPs unblocked once threat cleared	auto_responder.py --mode recover	SOAR_RECOVERY_COMPLETE; iptables rules removed; service restored
Review	Full incident timeline reconstructed and documented	Splunk correlation search	Complete IOC → Attack → Response timeline visible in single query
RACI Matrix
Activity	SOC Analyst	CISO	Network Engineer	Automation (SOAR)
Dark web monitoring	R	I	—	A
IOC extraction	R, A	I	—	—
SIEM alert triage	R	I	—	A
Incident classification	R, A	C	—	—
Attack detection (AI/Zeek)	—	I	C	R, A
IP block execution	—	A	R	R
Slice QoS protection	—	A	R	—
Service recovery	R	A	C	R
Post-incident review	R	A	C	—
R = Responsible · A = Accountable · C = Consulted · I = Informed

Key Metrics
Metric	Definition	Result
MTTR (Mean Time to Respond)	SOAR triggered → iptables rule applied	1.084 seconds
IOCs Extracted	Total dark web threats processed	3
IOCs Auto-Blocked	HIGH + MEDIUM confidence IOCs blocked	2
IOCs Skipped (Manual Review)	LOW confidence IOCs requiring analyst judgment	1
AI Anomalies Detected	Isolation Forest flagged connections	20 of 323,402 scored
Zeek Detection Types	Custom 5G-aware notices fired	DDoS_SYN_Flood, DDoS_GTP_Flood
Attack Vector Specificity	Port targeted in addition to standard flood	GTP-U (port 2152) — 5G user plane protocol
Network Slices Protected	Slices with enforced QoS	3 (eMBB, URLLC, mMTC)
Note on AI Baseline
The Isolation Forest model was trained on a short baseline capture (7 records) during this lab run, which limited the model's ability to cleanly isolate the attacker IP among the anomalies returned. A 5-minute (or longer) baseline capture would produce a tighter "normal" traffic profile and more precisely isolate the attacker. This is documented as a known lab constraint rather than a detection failure, the attacker IP (192.168.56.105) was still correctly flagged among the anomalies returned.

MITRE ATT&CK Mapping
Technique	ID	Description
Network Denial of Service: Direct Network Flood	T1498.001	SYN flood + UDP flood against 5G core
Endpoint Denial of Service: Service Exhaustion Flood	T1499.002	GTP-U (port 2152) targeted exhaustion of UPF resources
Resource Hijacking	T1496	Sustained resource consumption on 5G core infrastructure
Incident Timeline (Actual Lab Timestamps)
text
T+0:00:00   null_meridian dark web post ingested
T+0:00:02   IOC extraction complete - 3 IOCs written to blacklist
T+0:00:04   IOC events visible in Splunk (sourcetype=threat_intel)
T+0:05:00   DDoS attack launched from VM4 - SYN flood on port 80 +
            UDP flood on port 2152 (GTP-U / 5G user plane)
T+0:05:08   Zeek raises DDoS_SYN_Flood notice
T+0:05:11   Zeek raises DDoS_GTP_Flood notice (5G-specific detection)
T+0:06:30   AI anomaly detector run - 20 anomalies flagged,
            attacker IP (192.168.56.105) among results
T+0:06:32   Anomaly events sent to Splunk
            (sourcetype=ai_anomaly_detection)
T+0:08:00   SOAR auto_responder.py executed
T+0:08:01   iptables DROP rules applied - MTTR 1.084 seconds
T+0:08:01   SOAR_BLOCK_EXECUTED logged to Splunk
T+0:10:00   Threat cleared - recovery initiated
T+0:10:02   iptables rules removed - service restored
T+0:10:02   SOAR_RECOVERY_COMPLETE logged to Splunk
Full Incident Timeline in Splunk
The complete incident lifecycle was captured in a single Splunk correlation query:

text
index=* (sourcetype=threat_intel OR
         sourcetype=ai_anomaly_detection OR
         sourcetype=soar_response)
| eval stage=case(
    sourcetype=="threat_intel", "1_IOC_DETECTED",
    sourcetype=="ai_anomaly_detection", "2_ATTACK_DETECTED",
    sourcetype=="soar_response", "3_RESPONSE_TAKEN")
| table _time, stage, sourcetype, attacker_ip,
        src_ip, ip, action, confidence
| sort _time
Stages visible in Splunk:

Stage	Sourcetype	IPs	Count
1_IOC_DETECTED	threat_intel	192.168.56.105, 192.168.56.110, 192.168.56.111	3
2_ATTACK_DETECTED	ai_anomaly_detection	192.168.56.105, 192.168.56.1, 192.168.56.102, 192.168.56.104	20
3_RESPONSE_TAKEN	soar_response	192.168.56.105, 192.168.56.110	9+
Conclusion
This incident demonstrates a complete automated detection-to-remediation cycle for a 5G-aware DDoS attack targeting critical infrastructure. The integration of:

Dark web threat intelligence (Phase 2)

AI-augmented anomaly detection (Phase 5)

Sub-2-second automated mitigation (Phase 6)

…reflects the response capability required for telecoms operators managing live 5G network slices with contractual SLA obligations on enterprise and public-sector traffic.

Key Takeaway: The automation gap - between "threat surfaced" and "IOC actioned" - was collapsed to 1.084 seconds. In a live production environment, this capability would translate directly to reduced SLA breach risk, preserved revenue from enterprise contracts, and maintained public-sector trust.

References
Project Gatekeeper - Identity Security

MITRE ATT&CK T1498

ITIL 4 Incident Management

Author: Oluwatobi Babalola
GitHub: @BabsBBG
LinkedIn: Oluwatobi Babalola