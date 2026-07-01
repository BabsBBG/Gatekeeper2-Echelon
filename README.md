# Gatekeeper 2 - Operation Echelon

### 5G-Aware Cyber Threat Intelligence & Automated DDoS Defense Lab

[![Security](https://img.shields.io/badge/5G-SOC%20Lab-blue)](https://github.com/BabsBBG/Gatekeeper2-Echelon)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB)](https://python.org)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise-0078D4)](https://splunk.com)
[![Open5GS](https://img.shields.io/badge/Open5GS-2.8.0-green)](https://open5gs.org)
[![UERANSIM](https://img.shields.io/badge/UERANSIM-3.3.0-orange)](https://github.com/aligungr/UERANSIM)
[![MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**Continuation of [Project Gatekeeper](https://github.com/BabsBBG/project-gatekeeper)** — where Gatekeeper secured the identity layer of the Helix-Pulse merger, Operation Echelon secures the network layer of Pulse's 5G infrastructure.

---

## Table of Contents

1. [The Real Story](#the-real-story)
2. [What This Demonstrates](#what-this-demonstrates)
3. [Architecture](#architecture)
4. [Lab Environment](#lab-environment)
5. [Key Metrics](#key-metrics)
6. [Phases](#phases)
7. [Hiccups & Fixes](#hiccups--fixes)
8. [Project Structure](#project-structure)
9. [Author](#author)

---

## The Real Story

Helix Communications, having secured its identity posture through Project Gatekeeper, completes the acquisition of **Pulse**, a regional 5G operator serving 340,000 subscribers across North England and the Midlands.

Pulse brings no mature security capability into the deal: no SIEM, no threat intelligence function, no SOC. The Helix CISO raises a Priority 1 concern:

> *"We are absorbing a 5G core network during a publicly announced transaction window. Threat actors monitor M&A announcements. We have approximately 90 days before this becomes a target."*

That assessment proves optimistic by 60 days.

**Day 31 post-announcement:** Dark web monitoring surfaces a post from threat actor **null_meridian** — a commissioned DDoS campaign specifically targeting the enterprise URLLC slice serving local authority contracts. The SOC has 72 hours.

This project is the SOC's response — a complete pipeline from dark web threat intelligence through to automated, sub-second mitigation.

---

## What This Demonstrates

- Threat intelligence extraction and IOC management
- SIEM integration and detection engineering (Splunk)
- 5G Standalone core deployment and network slicing (Open5GS + UERANSIM)
- AI-augmented anomaly detection (Isolation Forest)
- Automated SOAR incident response
- ITIL-aligned incident lifecycle management

---

## Architecture

```
[Dark Web Simulation] → [IOC Extraction] → [SQLite Blacklist]
                                ↓
                          [Splunk SIEM]
                                ↓
                    [5G Network — Open5GS Core]
                       (AMF / SMF / UPF / Slicing)
                                ↓
                  [UERANSIM — gNB + UE Simulation]
                                ↓
                  [DDoS Attack Simulation — hping3]
                                ↓
              [Zeek Detection + AI Anomaly Detection]
                                ↓
                  [SOAR Auto-Response — iptables]
                                ↓
                      [Splunk Incident Timeline]
```

---

## Lab Environment

| VM | Role | IP | Key Software |
|----|------|-----|--------------|
| VM1 | 5G Core | 192.168.56.102 | Open5GS, MongoDB (Docker), Node.js |
| VM2 | RAN Simulation | 192.168.56.103 | UERANSIM (gNB + UE) |
| VM3 | SOC Stack | 192.168.56.104 | Splunk, Zeek, Python (Isolation Forest) |
| VM4 | Attacker | 192.168.56.105 | hping3 |

**OS:** Ubuntu 24.04 LTS on all VMs
**Network:** VirtualBox Host-only (192.168.56.0/24) + NAT for internet access
**Safety Notice:** All attack simulation conducted within isolated VirtualBox lab. `null_meridian` is a fictional threat actor.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **IOCs Extracted** | 3 |
| **IOCs Auto-Blocked** | 2 (HIGH + MEDIUM confidence) |
| **AI Anomalies Detected** | 20 (out of 323,402 connections) |
| **MTTR** | **1.084 seconds** |
| **Zeek Detections** | DDoS_SYN_Flood, DDoS_GTP_Flood (5G-specific) |
| **Network Slices** | 3 (eMBB, URLLC, mMTC) with enforced QoS |
| **UE IP** | 10.45.0.9 |

---

## Phases

### Phase 1 — Lab Architecture & Base Setup

Four Ubuntu 24.04 LTS VMs provisioned in VirtualBox, each with dual network adapters — NAT for internet access during installs, Host-only for lab-to-lab communication on the 192.168.56.0/24 subnet.

| VM | Role | Installed |
|----|------|-----------|
| VM1 | Open5GS core | Open5GS, MongoDB (Docker), Node.js, Python3 |
| VM2 | UERANSIM | UERANSIM build, tmux, build-essential |
| VM3 | SOC stack | Splunk, Zeek, Grafana, InfluxDB, Python venv |
| VM4 | Attacker | hping3, net-tools |

![Node.js installed](screenshots/phase1/phase1_01_nodejs_installed.png)
![UERANSIM built](screenshots/phase1/phase1_02_ueransim_built.png)
![Folder structure](screenshots/phase1/phase1_03_folder_structure.png)
![InfluxDB active](screenshots/phase1/phase1_04_influxdb_active.png)
![Grafana active](screenshots/phase1/phase1_05_grafana_active.png)

---

### Phase 2 — Threat Intelligence Pipeline

Simulated dark web threat data (`darkweb_data.json`, `multi_attacker_feed.json`) is parsed by `ioc_extractor.py`, which extracts attacker IP, method, target slice, and confidence rating into a SQLite blacklist managed by `blacklist_db.py`.

**IOCs extracted:**

| IP | Method | Confidence | Slice |
|----|--------|------------|-------|
| 192.168.56.105 | UDP flood + SYN flood | HIGH | URLLC |
| 192.168.56.110 | HTTP flood | MEDIUM | eMBB |
| 192.168.56.111 | ICMP flood | LOW | mMTC |

**Run it:**

```bash
cd ~/gatekeeper2-echelon
python3 threat_intel/ioc_extractor.py
```

![Darkweb data files](screenshots/phase2/phase2_01_darkweb_data.png)
![IOC extractor output](screenshots/phase2/phase2_02_ioc_extractor_output.png)
![Blacklist active](screenshots/phase2/phase2_03_blacklist_active.png)
![SQLite queries](screenshots/phase2/phase2_04_sqlite_queries.png)
![File structure](screenshots/phase2/phase2_05_file_structure.png)

---

### Phase 3 — SIEM Integration (Splunk)

IOCs and all downstream events are pushed to Splunk via HTTP Event Collector (HEC). `splunk_forwarder.py` handles event delivery for three event types — IOC, AI anomaly, SOAR action. `siem_pipeline.py` orchestrates the full ingestion run. Eight SPL detection queries are documented in `splunk_queries.md`, including a full incident-timeline correlation query.

**HEC config:**
- URL: `https://192.168.56.104:8088/services/collector`
- SSL enabled — always use `https://`

**Test HEC:**

```bash
curl -k https://192.168.56.104:8088/services/collector \
  -H "Authorization: Splunk <token>" \
  -d '{"event": "HEC test"}'
```

![SIEM scripts](screenshots/phase3/phase3_01_siem_scripts.png)
![Zeek version](screenshots/phase3/phase3_02_zeek_version.png)
![Grafana welcome](screenshots/phase3/phase3_03_grafana_welcome.png)
![Splunk login](screenshots/phase3/phase3_04_splunk_login.png)
![Splunk IOC events](screenshots/phase3/phase3_05_splunk_ioc_events.png)
![Dashboard edit](screenshots/phase3/phase3_06_splunk_dashboard_edit.png)
![Dashboard final](screenshots/phase3/phase3_07_splunk_dashboard_final.png)

---

### Phase 4 — 5G Network Simulation

Open5GS runs a complete 5G Standalone core (AMF, SMF, UPF, NRF, UDM, AUSF, PCF) on VM1. UERANSIM simulates a base station (gNB) and connected device (UE) on VM2, registered against a subscriber profile (IMSI `999700000000001`) in Open5GS. Three network slices are configured — eMBB, URLLC, mMTC — with Linux `tc` HTB traffic shaping enforcing slice-specific QoS. URLLC (the enterprise slice) receives guaranteed bandwidth at the highest priority.

Open5GS and UERANSIM were operated entirely via CLI and systemd — consistent with how 5G core infrastructure is managed in production telecoms environments. The WebUI was used only for initial subscriber registration.

**Slice design:**

| Slice | SST | Service | Rate | Ceiling | Priority |
|-------|-----|---------|------|---------|----------|
| URLLC | 2 | Enterprise/local authority | 50mbit | 70mbit | 1 (protected) |
| eMBB | 1 | Residential | 30mbit | 50mbit | 2 |
| mMTC | 3 | IoT | 10mbit | 20mbit | 3 |

**Start the network:**

```bash
# VM1 — Open5GS already running as systemd services
sudo systemctl status open5gs-amfd

# VM2 — Terminal 1
cd ~/UERANSIM
sudo ./build/nr-gnb -c config/open5gs-gnb.yaml

# VM2 — Terminal 2
sudo ./build/nr-ue -c config/open5gs-ue.yaml
```

![AMF active port 38412](screenshots/phase4/phase4_01_amf_active_port38412.png)
![AMF status NF connected](screenshots/phase4/phase4_02_amf_status_nf_connected.png)
![Open5GS services](screenshots/phase4/phase4_03_open5gs_services.png)
![gNB NG Setup success](screenshots/phase4/phase4_04_gnb_ngsetup_success.png)
![AMF log gNB added](screenshots/phase4/phase4_05_amf_log_gnb_added.png)
![tc QoS classes](screenshots/phase4/phase4_06_tc_qos_classes.png)
![uesimtun0 IP assigned](screenshots/phase4/phase4_07_uesimtun0_ip_assigned.png)

---

### Phase 5 — Attack Simulation & AI Detection

A DDoS attack is launched from VM4 using `hping3` — a SYN flood plus a UDP flood specifically targeting port 2152 (GTP-U, the 5G user plane protocol). This targets the 5G data path directly rather than a generic service port, making this a 5G-aware attack. Zeek monitors lab traffic with a custom detection script (`ddos_detect.zeek`) that raises notices for both attack types. `anomaly_detector.py` trains an Isolation Forest model on baseline traffic and scores live traffic during the attack, flagging anomalous connections and forwarding them to Splunk.

**Attack commands (VM4):**

```bash
sudo hping3 -S --flood -V -p 80 -I enp0s8 192.168.56.102
sudo hping3 --udp --flood -V -p 2152 -I enp0s8 192.168.56.102
```

**Run AI detection (VM3):**

```bash
source ~/echelon-env/bin/activate
python3 threat_intel/anomaly_detector.py
```

![hping3 version](screenshots/phase5/phase5_01_hping3_version.png)
![Baseline captured](screenshots/phase5/phase5_02_baseline_captured.png)
![AI packages OK](screenshots/phase5/phase5_03_ai_packages_ok.png)
![SYN flood attack](screenshots/phase5/phase5_04_hping3_syn_flood.png)
![UDP flood attack](screenshots/phase5/phase5_05_hping3_udp_flood.png)
![Zeek DDoS notice](screenshots/phase5/phase5_06_zeek_ddos_notice.png)
![conn.log growth](screenshots/phase5/phase5_07_conn_log_growth.png)
![Splunk anomaly stats](screenshots/phase5/phase5_08_splunk_anomaly_stats.png)
![AI detection output](screenshots/phase5/phase5_09_ai_detection_output.png)
![ddos_simulation files](screenshots/phase5/phase5_10_ddos_simulation_files.png)
![Splunk anomaly events](screenshots/phase5/phase5_11_splunk_anomaly_events.png)

---

### Phase 6 — SOAR & Automated Mitigation

`auto_responder.py` is the SOAR engine. It reads the active blacklist, automatically blocks HIGH and MEDIUM confidence attacker IPs via iptables, logs every action to Splunk with precise timestamps, and updates the blacklist status. LOW confidence IOCs are skipped and flagged for manual analyst review. A recovery mode unblocks IPs and restores service once the threat is cleared.

**Run response:**

```bash
sudo python3 mitigation/auto_responder.py --mode respond
```

**Run recovery:**

```bash
sudo python3 mitigation/auto_responder.py --mode recover
```

**Result:** MTTR (SOAR trigger → iptables rule applied) of **1.084 seconds**. 2 IPs blocked automatically, 1 skipped for manual review.

![SOAR error debug](screenshots/phase6/phase6_01_soar_error.png)
![iptables blocked](screenshots/phase6/phase6_02_iptables_blocked.png)
![SOAR summary](screenshots/phase6/phase6_03_soar_summary.png)
![Splunk SOAR events](screenshots/phase6/phase6_04_splunk_soar_events.png)
![Incident timeline](screenshots/phase6/phase6_05_incident_timeline.png)

---

### Phase 7 — Visualization & Final Dashboard

A fully populated Splunk dashboard with four panels — IOC events, AI anomaly detections, attack traffic timechart showing the DDoS spike, and the complete SOAR audit trail showing automated block and recovery events.

![iptables recovered](screenshots/phase7/phase7_01_iptables_recovered.png)
![Splunk recovery event](screenshots/phase7/phase7_02_splunk_recovery_event.png)
![Incident timeline final](screenshots/phase7/phase7_03_incident_timeline_final.png)
![Attack traffic timechart](screenshots/phase7/phase7_04_attack_traffic_timechart.png)
![Dashboard all panels](screenshots/phase7/phase7_05_dashboard_soar_highthreat_panels.png)

---

## Hiccups & Fixes

### 1. MongoDB CPU Instruction Set Incompatibility

**Issue:** Native MongoDB 7.0 package failed to start with `core-dump (signal=ILL)` on VirtualBox VM.

**Cause:** MongoDB 7.0 requires AVX CPU instructions which the virtualised CPU did not support.

**Fix:** Used Docker with MongoDB 4.4:

```bash
sudo docker run -d --name mongodb -p 27017:27017 mongo:4.4
```

---

### 2. AMF guami Configuration Error

**Issue:** AMF failed to start with `ERROR: No amf.guami` and `FATAL: Open5GS is terminated`.

**Cause:** Open5GS v2.8.0 requires explicit `guami` configuration not covered in older documentation.

**Fix:** Added correct `guami` block to `/etc/open5gs/amf.yaml`:

```yaml
amf:
  guami:
    - plmn_id:
        mcc: 999
        mnc: 70
      amf_id:
        region: 2
        set: 1
        pointer: 0
```

---

### 3. AMF Timer Encoding Error

**Issue:** AMF crashed with `Not support GPRS Timer 3 [3240]` after guami fix.

**Cause:** The `t3512` timer value must be a multiple of 600 seconds due to GPRS Timer 3 bit encoding. 3240 is not a valid multiple.

**Fix:** Changed value to `3600`:

```yaml
  time:
    t3502:
      value: 720
    t3512:
      value: 3600
```

---

### 4. Splunk HEC Protocol Mismatch

**Issue:** HEC curl returned `Received HTTP/0.9 when not allowed`.

**Cause:** HEC had SSL enabled but scripts were using `http://` instead of `https://`.

**Fix:** Changed all HEC URLs to `https://` and added `-k` flag for self-signed certificates.

---

### 5. Zeek Script Type Clash

**Issue:** Zeek script failed with `type clash in comparison (c$id$proto == tcp)`.

**Cause:** Zeek expects numeric protocol IDs, not string literals.

**Fix:**

```zeek
if (c$id$proto == 6) { ... }   # TCP
if (c$id$proto == 17) { ... }  # UDP
```

---

### 6. Zeek Log Location Confusion

**Issue:** `conn.log` not found in `/opt/zeek/logs/current/`.

**Cause:** Zeek writes logs to the current working directory when run without `--logdir`.

**Fix:** Used `ls -la conn.log` from the project root.

---

### 7. Isolation Forest Baseline Too Small

**Issue:** Attacker IP not clearly singled out among AI anomaly results.

**Cause:** Baseline was only 7 records — insufficient for Isolation Forest to learn meaningful normal traffic patterns.

**Note:** Documented as a known lab constraint. A 5-minute baseline produces tighter isolation. The attacker IP was still correctly included among the flagged anomalies.

---

### 8. UPF Internet Routing (VirtualBox NAT Limitation)

**Issue:** `ping -I ogstun 8.8.8.8` failed with 100% packet loss despite correct iptables MASQUERADE rules.

**Cause:** VirtualBox NAT engine does not forward packets originating from secondary VM subnets to the internet — a hypervisor-level constraint, not a Linux routing problem (confirmed via tcpdump showing packets leaving ogstun but never appearing on enp0s3).

**Impact:** None — all Phase 5/6 attacks target internal lab IPs over the Host-only network, which functions correctly. Documented in `5g_network/lab_limitations.md`.

---

## Project Structure

```
gatekeeper2-echelon/
├── SCENARIO.md                         # Full threat narrative
├── itil_workflow.md                    # ITIL incident mapping
├── requirements.txt
│
├── darkweb_simulation/
│   ├── darkweb_data.json               # null_meridian primary threat
│   └── multi_attacker_feed.json        # 3 threat actors
│
├── threat_intel/
│   ├── blacklist_db.py                 # SQLite database manager
│   ├── ioc_extractor.py                # IOC extraction pipeline
│   ├── anomaly_detector.py             # Isolation Forest AI detection
│   └── blacklist.db                    # 3 active IOCs
│
├── siem_integration/
│   ├── splunk_forwarder.py             # HEC client (4 send functions)
│   ├── siem_pipeline.py                # Blacklist → Splunk orchestration
│   └── splunk_queries.md               # 8 SPL detection queries
│
├── 5g_network/
│   ├── slices.md                       # Slice design and QoS config
│   ├── qos_preservation_evidence.md
│   └── lab_limitations.md
│
├── ddos_simulation/
│   ├── ddos_detect.zeek                # Zeek DDoS detection script
│   ├── baseline_conn.log               # Normal traffic baseline
│   ├── attack_conn.log                 # Attack-period traffic
│   └── anomaly_results.json            # AI detection output
│
├── mitigation/
│   └── auto_responder.py               # SOAR auto-responder
│
└── screenshots/
    ├── phase1/
    ├── phase2/
    ├── phase3/
    ├── phase4/
    ├── phase5/
    ├── phase6/
    └── phase7/
```

---

## Quick Start

```bash
# 1. Extract IOCs
cd ~/gatekeeper2-echelon
python3 threat_intel/ioc_extractor.py

# 2. Send to Splunk
python3 siem_integration/siem_pipeline.py

# 3. Start 5G Network (VM2 — two terminals)
sudo ./build/nr-gnb -c config/open5gs-gnb.yaml
sudo ./build/nr-ue -c config/open5gs-ue.yaml

# 4. Launch attack (VM4) and detect (VM3)
sudo hping3 -S --flood -V -p 80 -I enp0s8 192.168.56.102
python3 threat_intel/anomaly_detector.py

# 5. Auto-block (VM1)
sudo python3 mitigation/auto_responder.py --mode respond
```

---

## Author

**Oluwatobi Babalola**
GitHub: [@BabsBBG](https://github.com/BabsBBG)
LinkedIn: [Oluwatobi Babalola](https://linkedin.com/in/oluwatobi-babalola)

---

**The automation gap between "threat surfaced" and "IOC actioned" collapsed to 1.084 seconds.**