from math import inf
import heapq
import struct
import socket
import os

from scapy.all import Ether, IP, UDP, Raw, wrpcap


def make_undirected_graph(adj):
    g = {}
    for u in adj:
        g.setdefault(u, {})
        for v, c in adj[u].items():
            g.setdefault(v, {})
            g[u][v] = min(c, g[u].get(v, c))
            g[v][u] = min(c, g[v].get(u, c))
    return g


def dijkstra(graph, source):
    dist = {node: float('inf') for node in graph}
    prev = {node: None for node in graph}
    dist[source] = 0
    
    pq = [(0, source)] #distance, node
    
    while pq:
        # Get the node with the smallest distance
        current_dist, u = heapq.heappop(pq)
        if current_dist > dist[u]:
            continue
            
        # Explore neighbors
        for v, weight in graph[u].items():
            distance = current_dist + weight
            
            # If a shorter path to v is found
            if distance < dist[v]:
                dist[v] = distance
                prev[v] = u
                heapq.heappush(pq, (distance, v))
                
    return dist, prev


def reconstruct_path(prev, src, dst):
    if prev[dst] is None and dst != src:
        return None
    path = [dst]
    cur = dst
    while cur != src:
        cur = prev[cur]
        if cur is None:
            return None
        path.append(cur)
    path.reverse()
    return path


def print_spt(graph, root):
    graph = make_undirected_graph(graph)
    dist, prev = dijkstra(graph, root)
    print(f"===== CÂY ĐƯỜNG ĐI NGẮN NHẤT (SPT) TỪ {root} =====")
    for node in sorted(graph.keys()):
        if node == root:
            print(f"{root}: cost = 0, path = [{root}]")
            continue
        if dist[node] == inf:
            print(f"{node}: KHÔNG TỚI ĐƯỢC")
            continue
        path = reconstruct_path(prev, root, node)
        print(f"{node}: cost = {dist[node]}, path = {' -> '.join(path)}")
    print()


def assign_addresses(nodes):
    """
    Gán IP / MAC đơn giản cho từng router:
      R1 -> 10.0.0.1, MAC 00:00:5e:00:00:01
      R2 -> 10.0.0.2, ...
    """
    ip_map = {}
    mac_map = {}
    for i, name in enumerate(sorted(nodes), start=1):
        ip_map[name] = f"10.0.0.{i}"
        # lấy i trong [1, 254] -> 2 hex
        last_octet = i & 0xFF
        mac_map[name] = f"00:00:5e:00:00:{last_octet:02x}"
    return ip_map, mac_map


def ip_to_net24(ip):
    """
    Biến IP host thành network /24, ví dụ:
      10.0.0.3 -> 10.0.0.0
    (Để dùng làm network trong các entry RIP)
    """
    parts = ip.split(".")
    parts[-1] = "0"
    return ".".join(parts)


# ======================
# RIP – Distance Vector
# ======================

class RIPRouter:
    def __init__(self, name, neighbors):
        """
        name: tên router (str)
        neighbors: dict{neighbor_name: cost}
        """
        self.name = name
        self.neighbors = neighbors  # cost trực tiếp
        # bảng định tuyến: dest -> (cost, next_hop)
        self.table = {}
        self.init_table()

    def init_table(self):
        self.table[self.name] = (0, self.name)
        for nb, c in self.neighbors.items():
            self.table[nb] = (c, nb)

    def prepare_update(self):
        """
        Chuẩn bị vector khoảng cách để gửi:
        trả về dict{dest: cost}
        """
        return {dst: cost for dst, (cost, _) in self.table.items()}

    def recv_update(self, from_nb, vector):
        """
        Nhận bảng vector khoảng cách từ neighbor.
        vector: dict{dest: cost}
        """
        changed = False
        if from_nb not in self.neighbors:
            return False

        cost_to_nb = self.neighbors[from_nb]
        for dest, their_cost in vector.items():
            if their_cost == inf:
                continue
            new_cost = cost_to_nb + their_cost
            if (dest not in self.table) or (new_cost < self.table[dest][0]):
                self.table[dest] = (new_cost, from_nb)
                changed = True
        return changed


def build_rip_response(routes):
    """
    Tạo payload RIP v2 (Response) từ danh sách routes:
      routes: list[(ip_str, mask_str, metric)]
    """
    # Header: Command=2, Version=2, Zero=0
    header = struct.pack("!BBH", 2, 2, 0)

    entries = b""
    for ip, mask, metric in routes:
        afi = 2          # Address Family ID: IP
        route_tag = 0
        ip_bytes = socket.inet_aton(ip)
        mask_bytes = socket.inet_aton(mask)
        next_hop = socket.inet_aton("0.0.0.0")
        entries += struct.pack("!HH4s4s4sI",
                               afi,
                               route_tag,
                               ip_bytes,
                               mask_bytes,
                               next_hop,
                               metric)
    return header + entries


def simulate_rip_with_pcap(graph, ip_map, mac_map, max_rounds=10):
    """
    Chạy mô phỏng RIP trên đồ thị (distance vector), đồng thời sinh gói RIPv2
    multicast (224.0.0.9) vào list pcap_packets.

    Trả về:
      - routers: dict{name: RIPRouter}
      - pcap_packets: list[Scapy Packet]
    """
    graph = make_undirected_graph(graph)
    routers = {name: RIPRouter(name, graph[name]) for name in graph}
    pcap_packets = []

    rip_multicast_ip = "224.0.0.9"
    rip_multicast_mac = "01:00:5e:00:00:09"

    for rnd in range(max_rounds):
        messages = []
        any_change = False

        for name, rtr in routers.items():
            vec = rtr.prepare_update()
            # gửi vector tới từng neighbor (logic thuật toán)
            for nb in rtr.neighbors:
                messages.append((nb, name, vec))

            # Đồng thời sinh 1 gói RIP v2 multicast để ghi vào PCAP
            routes = []
            for dest, cost in vec.items():
                if cost == inf:
                    continue
                net = ip_to_net24(ip_map[dest])
                routes.append((net, "255.255.255.0", int(cost)))
            if routes:
                payload = build_rip_response(routes)
                pkt = (
                    Ether(src=mac_map[name], dst=rip_multicast_mac) /
                    IP(src=ip_map[name], dst=rip_multicast_ip) /
                    UDP(sport=520, dport=520) /
                    Raw(payload)
                )
                pcap_packets.append(pkt)

        # Pha nhận và cập nhật bảng định tuyến
        for dst, src, vec in messages:
            changed = routers[dst].recv_update(src, vec)
            any_change = any_change or changed

        if not any_change:
            # đã hội tụ
            break

    return routers, pcap_packets


# ======================
# OSPF – Link State + Dijkstra
# ======================

class OSPFRouter:
    def __init__(self, name, neighbors):
        self.name = name
        self.neighbors = neighbors
        # LSDB: router_name -> {neighbor: cost}
        self.lsdb = {self.name: dict(self.neighbors)}
        # bảng định tuyến: dest -> (cost, next_hop)
        self.table = {}

    def originate_lsa(self):
        """
        Phát tán LSA mô tả link của chính mình.
        """
        return self.name, dict(self.neighbors)

    def recv_lsa(self, origin, adj):
        """
        Nhận LSA từ router 'origin'.
        """
        old = self.lsdb.get(origin)
        if old is None or old != adj:
            self.lsdb[origin] = dict(adj)
            return True
        return False

    def compute_shortest_paths(self):
        """
        Dùng Dijkstra trên LSDB để tính bảng định tuyến.
        """
        g = make_undirected_graph(self.lsdb)
        dist, prev = dijkstra(g, self.name)
        self.table = build_routing_table(self.name, dist, prev)


def build_routing_table(source, dist, prev):
    """
    Xây bảng định tuyến dest -> (cost, next_hop) từ kết quả Dijkstra.
    """
    table = {}
    for dest, d in dist.items():
        if d == inf:
            continue
        if dest == source:
            table[dest] = (0, source)
            continue
        nh = dest
        while prev[nh] is not None and prev[nh] != source:
            nh = prev[nh]
        if prev[nh] is None:
            continue
        table[dest] = (d, nh)
    return table


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
    Tạo payload OSPFv2 Hello (header + body) đơn giản.
    Cheksum = 0 (Wireshark vẫn decode được).
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


def simulate_ospf_with_pcap(graph, ip_map, mac_map, max_rounds=5):
    """
    Mô phỏng OSPF dạng link-state: flood LSA + chạy SPF.
    Mỗi vòng, mỗi router gửi 1 gói OSPF Hello (AllSPFRouters) để ghi vào PCAP.

    Trả về:
      - routers: dict{name: OSPFRouter}
      - pcap_packets: list[Scapy Packet]
    """
    graph = make_undirected_graph(graph)
    routers = {name: OSPFRouter(name, graph[name]) for name in graph}
    pcap_packets = []

    ospf_multicast_ip = "224.0.0.5"
    ospf_multicast_mac = "01:00:5e:00:00:05"

    for rnd in range(max_rounds):
        messages = []
        any_change = False

        for name, rtr in routers.items():
            # Flood LSA (logic link-state)
            origin, adj = rtr.originate_lsa()
            for nb in rtr.neighbors:
                messages.append((nb, origin, adj))

            # Tạo OSPF Hello packet để đưa vào PCAP
            hello = build_ospf_hello(
                router_id=ip_map[name],
                neighbors=[ip_map[nb] for nb in rtr.neighbors]
            )
            pkt = (
                Ether(src=mac_map[name], dst=ospf_multicast_mac) /
                IP(src=ip_map[name], dst=ospf_multicast_ip, proto=89) /
                Raw(hello)
            )
            pcap_packets.append(pkt)

        for dst, origin, adj in messages:
            changed = routers[dst].recv_lsa(origin, adj)
            any_change = any_change or changed

        if not any_change:
            break

    for rtr in routers.values():
        rtr.compute_shortest_paths()

    return routers, pcap_packets


def print_routing_table(label, table):
    print(f"--- Bảng định tuyến tại {label} ---")
    for dest, (cost, nh) in sorted(table.items()):
        print(f"  đích {dest:>3}  | cost = {cost:>2}  | next-hop = {nh}")
    print()


def main():
    # Đồ thị mạng ví dụ: nhiều node, nhiều edge
    graph = {
        "R1": {"R2": 1, "R3": 4},
        "R2": {"R1": 1, "R3": 2, "R4": 7},
        "R3": {"R1": 4, "R2": 2, "R4": 1, "R5": 3},
        "R4": {"R2": 7, "R3": 1, "R5": 1, "R6": 5},
        "R5": {"R3": 3, "R4": 1, "R6": 2},
        "R6": {"R4": 5, "R5": 2},
    }

    # Gán IP/MAC tự động
    nodes = graph.keys()
    ip_map, mac_map = assign_addresses(nodes)

    # Mô phỏng RIP + PCAP
    rip_routers, rip_pkts = simulate_rip_with_pcap(graph, ip_map, mac_map)
    print("===== KẾT QUẢ RIP =====")
    for name, rtr in rip_routers.items():
        print_routing_table(name, rtr.table)

    # Mô phỏng OSPF + PCAP
    ospf_routers, ospf_pkts = simulate_ospf_with_pcap(graph, ip_map, mac_map)
    print("===== KẾT QUẢ OSPF =====")
    for name, rtr in ospf_routers.items():
        print_routing_table(name, rtr.table)

    print_spt(graph, root="R1")

    all_pkts = rip_pkts + ospf_pkts

    t = 0.0
    for p in all_pkts:
        p.time = t
        t += 0.1


    folder_name = "routing/routing_dijkstra"

    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    file_path = os.path.join(folder_name, "routing_djikstra.pcap")
    
    wrpcap(file_path, all_pkts)
    print(f"--- Đã lưu file thành công tại: {file_path} ---")
    

    


if __name__ == "__main__":
    main()
