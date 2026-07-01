# Lab Limitations — VirtualBox NAT Constraint

## Internet Connectivity from UE

Ping from uesimtun0 to external IPs (8.8.8.8) fails due to
VirtualBox NAT engine limitation — the hypervisor NAT does not
forward packets originating from subnets other than the VM's
own IP (10.0.2.15).

## Impact on Project

Zero impact. All attack simulation (Phase 5) targets internal
lab IPs (192.168.56.102) via the Host-only network which works
correctly. Internet routing is not required for DDoS simulation,
Zeek detection, or SOAR response.

## Production Equivalent

In a real deployment, the UPF would route to a proper gateway
with NAT handled at the network edge — not a hypervisor NAT.
This constraint is specific to the VirtualBox lab environment.

## Core 5G Functionality Verified

- AMF: authenticated gNB and UE successfully
- SMF: PDU session established, IP assigned from 10.45.0.0/16
- UPF: ogstun interface up, GTP-U tunnel functional
- UE: uesimtun0 interface created with assigned IP
- Slices: SST 1,2,3 configured and advertised
