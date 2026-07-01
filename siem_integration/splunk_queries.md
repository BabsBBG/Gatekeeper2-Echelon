# Operation Echelon — Splunk SPL Detection Queries

## Query 1 — All IOC Events by Attacker IP
index=* sourcetype=threat_intel
| table _time, attacker_ip, threat_type, confidence, slice_target, target
| sort -_time

## Query 2 — High Confidence Threats Only
index=* sourcetype=threat_intel confidence=HIGH
| stats count by attacker_ip, threat_type, slice_target
| sort -count

## Query 3 — DDoS Alert — Connection Spike Detection
index=* sourcetype=ai_anomaly_detection
| timechart span=1m count as anomaly_count
| where anomaly_count > 10

## Query 4 — AI Anomaly Events by Source IP
index=* sourcetype=ai_anomaly_detection
| stats avg(bytes_orig) as avg_bytes, sum(pkts_orig) as total_pkts, count as detections by src_ip
| sort -detections

## Query 5 — SOAR Response Audit Trail
index=* sourcetype=soar_response
| table _time, ip, action, method, automated, operator
| sort -_time

## Query 6 — Full Incident Timeline
index=* (sourcetype=threat_intel OR sourcetype=ai_anomaly_detection OR sourcetype=soar_response)
| eval stage=case(
    sourcetype=="threat_intel", "1_IOC_DETECTED",
    sourcetype=="ai_anomaly_detection", "2_ATTACK_DETECTED",
    sourcetype=="soar_response", "3_RESPONSE_TAKEN")
| table _time, stage, sourcetype, attacker_ip, src_ip, ip, action, confidence
| sort _time

## Query 7 — MTTD Calculation
index=* sourcetype=threat_intel OR sourcetype=ai_anomaly_detection
| eval phase=if(sourcetype="threat_intel","detection_start","attack_confirmed")
| stats min(_time) as start_time by phase

## Query 8 — URLLC Slice Threat Summary
index=* sourcetype=threat_intel slice_target=URLLC
| stats count as urllc_threats, values(attacker_ip) as attacker_ips, values(threat_type) as methods
