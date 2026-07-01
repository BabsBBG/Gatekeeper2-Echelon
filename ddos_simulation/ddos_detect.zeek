# ddos_simulation/ddos_detect.zeek
# Gatekeeper 2: Operation Echelon — Zeek DDoS Detection (numeric proto)

@load base/frameworks/notice
@load base/protocols/conn

module DDoSDetect;

export {
    redef enum Notice::Type += {
        DDoS_SYN_Flood,
        DDoS_UDP_Flood,
        DDoS_GTP_Flood
    };
}

global syn_count: table[addr] of count &default=0;
global udp_count: table[addr] of count &default=0;

event connection_established(c: connection)
{
    local src = c$id$orig_h;
    # TCP protocol number = 6
    if (c$id$proto == 6) {
        syn_count[src] += 1;
        if (syn_count[src] > 50) {
            NOTICE([$note=DDoS_SYN_Flood,
                    $msg=fmt("SYN flood from %s — %d connections", src, syn_count[src]),
                    $src=src,
                    $identifier=fmt("syn-%s", src)]);
        }
    }
}

event connection_state_remove(c: connection)
{
    local src   = c$id$orig_h;
    local dport = c$id$resp_p;
    # UDP protocol number = 17
    if (c$id$proto == 17) {
        udp_count[src] += 1;
        if (dport == 2152/udp && udp_count[src] > 50) {
            NOTICE([$note=DDoS_GTP_Flood,
                    $msg=fmt("GTP-U flood (5G) from %s — %d pkts", src, udp_count[src]),
                    $src=src,
                    $identifier=fmt("gtp-%s", src)]);
        } else if (udp_count[src] > 100) {
            NOTICE([$note=DDoS_UDP_Flood,
                    $msg=fmt("UDP flood from %s — %d pkts", src, udp_count[src]),
                    $src=src,
                    $identifier=fmt("udp-%s", src)]);
        }
    }
}
