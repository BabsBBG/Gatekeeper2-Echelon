# Gatekeeper 2: Operation Echelon — Scenario Brief

**Classification:** Portfolio Lab — Fictional Scenario  
**Linked Project:** Project Gatekeeper (Phase 1)  
**Environment:** VirtualBox — Ubuntu 24.04 LTS VMs  

---

## Background

**Helix-Pulse Communications** acquires Spectranet, a regional
5G operator serving 340,000 subscribers across North England
and the Midlands.

Spectranet operates a 5G Standalone core with no formal SOC,
no SIEM, and no threat intelligence capability.

The Helix-Pulse CISO raises a Priority 1 concern:
> "We are absorbing a 5G core network during a publicly
> announced transaction window. Threat actors monitor M&A
> announcements. We have approximately 90 days before this
> becomes a target."

That assessment proves optimistic by 60 days.

---

## The Threat Event

**Day 31 post-announcement.**

Dark web monitoring surfaces a post from threat actor
**null_meridian** targeting Helix-Pulse's 5G infrastructure.
A commissioned DDoS campaign specifically targets the
enterprise URLLC slice serving local authority contracts.

The SOC has 72 hours.

---

## Lab Network

| VM | Role | IP |
|----|------|----|
| VM1 | Open5GS 5G Core | 192.168.56.102 |
| VM2 | UERANSIM (gNB + UE) | 192.168.56.103 |
| VM3 | SOC Stack (Splunk/Zeek/Grafana) | 192.168.56.104 |
| VM4 | Attacker (null_meridian) | 192.168.56.105 |

---

## Safety Notice

All attack simulation conducted within an isolated VirtualBox
lab. null_meridian is a fictional threat actor.
No real networks or IPs are targeted.

**Author:** Oluwatobi Babalola | **GitHub:** BabsBBG
