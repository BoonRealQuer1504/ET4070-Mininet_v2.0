from scapy.all import Ether, IP, UDP, TCP, Raw, wrpcap
import struct
import socket


def build_rip_response(routes):
    """
    routes: list[(ip_str, mask_str, metric)]
    Trả về payload RIP v2 (Response).
    """
    # RIP header: Command=2 (Response), Version=2, Zero=0
    header = struct.pack("!BBH", 2, 2, 0)

    entries = b""
    for ip, mask, metric in routes:
        afi = 2          # Address Family ID: IP
        route_tag = 0
        ip_bytes = socket.inet_aton(ip)
        mask_bytes = socket.inet_aton(mask)
        next_hop = socket.inet_aton("0.0.0.0")
        # Mỗi entry 20 bytes
        entries += struct.pack("!HH4s4s4sI",
                               afi,
                               route_tag,
                               ip_bytes,
                               mask_bytes,
                               next_hop,
                               metric)
    return header + entries


def generate_rip_packets():
    """
    Tạo vài gói RIP v2 (multicast 224.0.0.9).
    """
    pkts = []

    r1_ip, r2_ip = "192.168.1.1", "192.168.1.2"
    r1_mac, r2_mac = "00:00:5e:00:01:01", "00:00:5e:00:01:02"
    rip_multicast_ip = "224.0.0.9"
    rip_multicast_mac = "01:00:5e:00:00:09"

    # R1 quảng bá 1 route
    routes1 = [("192.168.10.0", "255.255.255.0", 1)]
    rip1 = build_rip_response(routes1)
    pkts.append(
        Ether(src=r1_mac, dst=rip_multicast_mac) /
        IP(src=r1_ip, dst=rip_multicast_ip) /
        UDP(sport=520, dport=520) /
        Raw(rip1)
    )

    # R2 quảng bá 1 route khác
    routes2 = [("192.168.20.0", "255.255.255.0", 1)]
    rip2 = build_rip_response(routes2)
    pkts.append(
        Ether(src=r2_mac, dst=rip_multicast_mac) /
        IP(src=r2_ip, dst=rip_multicast_ip) /
        UDP(sport=520, dport=520) /
        Raw(rip2)
    )

    # R1 gửi lại với metric tăng lên (mô phỏng link tệ hơn)
    routes1_changed = [("192.168.10.0", "255.255.255.0", 3)]
    rip1_ch = build_rip_response(routes1_changed)
    pkts.append(
        Ether(src=r1_mac, dst=rip_multicast_mac) /
        IP(src=r1_ip, dst=rip_multicast_ip) /
        UDP(sport=520, dport=520) /
        Raw(rip1_ch)
    )

    return pkts


# ==============================
# BGP: OPEN / KEEPALIVE / UPDATE
# ==============================

def build_bgp_open(my_as, hold_time, bgp_id):
    """
    Tạo BGP OPEN message (RFC 4271).
    """
    version = 4
    bgp_id_bytes = socket.inet_aton(bgp_id)
    opt_param_len = 0  # không gửi option

    body = struct.pack("!BHH4sB",
                       version,
                       my_as,
                       hold_time,
                       bgp_id_bytes,
                       opt_param_len)

    marker = b"\xff" * 16
    length = 19 + len(body)
    header = marker + struct.pack("!HB", length, 1)  # type=1 (OPEN)

    return header + body


def build_bgp_keepalive():
    """
    BGP KEEPALIVE: chỉ có header, không có body.
    """
    marker = b"\xff" * 16
    length = 19
    header = marker + struct.pack("!HB", length, 4)  # type=4 (KEEPALIVE)
    return header


def build_bgp_update(prefix="10.0.0.0",
                     prefix_len=24,
                     next_hop="203.0.113.1",
                     as_path_list=None):
    """
    BGP UPDATE message đơn giản:
    - Không có withdrawn routes.
    - Có ORIGIN, AS_PATH, NEXT_HOP.
    - NLRI: 1 prefix.
    """
    if as_path_list is None:
        as_path_list = [65001]

    marker = b"\xff" * 16

    # Withdrawn Routes
    withdrawn = b""
    withdrawn_len = 0

    # ORIGIN attribute: well-known mandatory, value = 0 (IGP)
    origin_attr = struct.pack("!BBBB", 0x40, 1, 1, 0)
    #   Flags=0x40, Type=1, Length=1, Value=0

    # AS_PATH attribute
    # Value = [SegmentType=2(AS_SEQUENCE), SegmentLength, AS1, AS2, ...]
    seg_type = 2  # AS_SEQUENCE
    seg_len = len(as_path_list)
    as_nums = b"".join(struct.pack("!H", asn) for asn in as_path_list)
    as_path_val = struct.pack("!BB", seg_type, seg_len) + as_nums
    as_path_attr = (
        struct.pack("!BB", 0x40, 2) +        # Flags, Type=2
        struct.pack("!B", len(as_path_val)) +  # Length
        as_path_val
    )

    # NEXT_HOP attribute
    nh_bytes = socket.inet_aton(next_hop)
    next_hop_attr = (
        struct.pack("!BB", 0x40, 3) +
        struct.pack("!B", 4) +
        nh_bytes
    )

    path_attrs = origin_attr + as_path_attr + next_hop_attr
    total_path_len = len(path_attrs)

    # NLRI
    prefix_bytes = socket.inet_aton(prefix)
    n_bytes = (prefix_len + 7) // 8
    nlri = struct.pack("!B", prefix_len) + prefix_bytes[:n_bytes]

    body = (
        struct.pack("!H", withdrawn_len) +
        withdrawn +
        struct.pack("!H", total_path_len) +
        path_attrs +
        nlri
    )

    length = 19 + len(body)
    header = marker + struct.pack("!HB", length, 2)  # type=2 (UPDATE)
    return header + body


def generate_bgp_packets():
    """
    Phiên BGP đơn giản giữa hai router:
      AS65001 (R_A) <-> AS65002 (R_B)
    gồm: TCP 3-way handshake, OPEN, KEEPALIVE, UPDATE.
    """
    pkts = []

    ip_a, ip_b = "203.0.113.1", "203.0.113.2"
    mac_a, mac_b = "00:00:5e:00:03:01", "00:00:5e:00:03:02"
    as_a, as_b = 65001, 65002

    cli_port = 50000
    srv_port = 179

    cli_seq = 100
    srv_seq = 1000

    # TCP 3-way handshake
    syn = Ether(src=mac_a, dst=mac_b) / IP(src=ip_a, dst=ip_b) / \
        TCP(sport=cli_port, dport=srv_port, seq=cli_seq, flags="S")
    cli_seq += 1

    synack = Ether(src=mac_b, dst=mac_a) / IP(src=ip_b, dst=ip_a) / \
        TCP(sport=srv_port, dport=cli_port, seq=srv_seq, ack=cli_seq, flags="SA")
    srv_seq += 1

    ack = Ether(src=mac_a, dst=mac_b) / IP(src=ip_a, dst=ip_b) / \
        TCP(sport=cli_port, dport=srv_port, seq=cli_seq, ack=srv_seq, flags="A")

    pkts += [syn, synack, ack]

    # BGP OPEN A -> B
    open_a = build_bgp_open(my_as=as_a, hold_time=90, bgp_id=ip_a)
    pkt_open_a = (
        Ether(src=mac_a, dst=mac_b) /
        IP(src=ip_a, dst=ip_b) /
        TCP(sport=cli_port, dport=srv_port,
            seq=cli_seq, ack=srv_seq, flags="PA") /
        Raw(open_a)
    )
    cli_seq += len(open_a)

    # BGP OPEN B -> A
    open_b = build_bgp_open(my_as=as_b, hold_time=90, bgp_id=ip_b)
    pkt_open_b = (
        Ether(src=mac_b, dst=mac_a) /
        IP(src=ip_b, dst=ip_a) /
        TCP(sport=srv_port, dport=cli_port,
            seq=srv_seq, ack=cli_seq, flags="PA") /
        Raw(open_b)
    )
    srv_seq += len(open_b)

    # KEEPALIVE hai bên
    ka = build_bgp_keepalive()
    pkt_ka_a = (
        Ether(src=mac_a, dst=mac_b) /
        IP(src=ip_a, dst=ip_b) /
        TCP(sport=cli_port, dport=srv_port,
            seq=cli_seq, ack=srv_seq, flags="PA") /
        Raw(ka)
    )
    cli_seq += len(ka)

    pkt_ka_b = (
        Ether(src=mac_b, dst=mac_a) /
        IP(src=ip_b, dst=ip_a) /
        TCP(sport=srv_port, dport=cli_port,
            seq=srv_seq, ack=cli_seq, flags="PA") /
        Raw(ka)
    )
    srv_seq += len(ka)

    # UPDATE từ A quảng bá prefix 10.0.0.0/24
    update = build_bgp_update(prefix="10.0.0.0",
                              prefix_len=24,
                              next_hop=ip_a,
                              as_path_list=[as_a])
    pkt_update = (
        Ether(src=mac_a, dst=mac_b) /
        IP(src=ip_a, dst=ip_b) /
        TCP(sport=cli_port, dport=srv_port,
            seq=cli_seq, ack=srv_seq, flags="PA") /
        Raw(update)
    )
    cli_seq += len(update)

    pkts += [pkt_open_a, pkt_open_b, pkt_ka_a, pkt_ka_b, pkt_update]
    return pkts


# ==============================
# OSPF Hello
# ==============================

def build_ospf_hello(router_id,
                     area_id="0.0.0.0",
                     netmask="255.255.255.0",
                     hello_interval=10,
                     options=0x02,
                     priority=1,
                     dead_interval=40,
                     dr=None,
                     bdr=None,
                     neighbors=None):
    """
    Tạo payload OSPFv2 Hello (header + body).
    Checksum đặt 0 cho đơn giản (Wireshark vẫn decode được).
    """
    if neighbors is None:
        neighbors = []
    if dr is None:
        dr = router_id
    if bdr is None:
        bdr = "0.0.0.0"

    rid_bytes = socket.inet_aton(router_id)
    area_bytes = socket.inet_aton(area_id)
    netmask_bytes = socket.inet_aton(netmask)
    dr_bytes = socket.inet_aton(dr)
    bdr_bytes = socket.inet_aton(bdr)

    # Hello body
    body = (
        netmask_bytes +
        struct.pack("!HBBI", hello_interval, options, priority, dead_interval) +
        dr_bytes +
        bdr_bytes
    )

    for nid in neighbors:
        body += socket.inet_aton(nid)

    # OSPF header
    version = 2
    pkt_type = 1  # Hello
    pkt_len = 24 + len(body)
    checksum = 0
    autype = 0
    auth = b"\x00" * 8

    header = struct.pack("!BBH4s4sHH8s",
                         version,
                         pkt_type,
                         pkt_len,
                         rid_bytes,
                         area_bytes,
                         checksum,
                         autype,
                         auth)

    return header + body


def generate_ospf_packets():
    """
    Hai router gửi OSPF Hello tới AllSPFRouters 224.0.0.5.
    """
    pkts = []

    r1_ip, r2_ip = "10.1.1.1", "10.1.1.2"
    r1_mac, r2_mac = "00:00:5e:00:02:01", "00:00:5e:00:02:02"
    ospf_multicast_ip = "224.0.0.5"
    ospf_multicast_mac = "01:00:5e:00:00:05"

    hello1 = build_ospf_hello(router_id=r1_ip,
                              neighbors=[r2_ip])
    hello2 = build_ospf_hello(router_id=r2_ip,
                              neighbors=[r1_ip])

    pkts.append(
        Ether(src=r1_mac, dst=ospf_multicast_mac) /
        IP(src=r1_ip, dst=ospf_multicast_ip, proto=89) /
        Raw(hello1)
    )

    pkts.append(
        Ether(src=r2_mac, dst=ospf_multicast_mac) /
        IP(src=r2_ip, dst=ospf_multicast_ip, proto=89) /
        Raw(hello2)
    )

    return pkts


# ==============================
# MAIN: sinh file PCAP
# ==============================

def main():
    rip_pkts = generate_rip_packets()
    bgp_pkts = generate_bgp_packets()
    ospf_pkts = generate_ospf_packets()

    all_pkts = rip_pkts + ospf_pkts + bgp_pkts

    wrpcap("routing_demo.pcap", all_pkts)
    print("Đã tạo file routing_demo.pcap – hãy mở bằng Wireshark và lọc:")
    print("  - rip")
    print("  - ospf")
    print("  - bgp")


if __name__ == "__main__":
    main()
