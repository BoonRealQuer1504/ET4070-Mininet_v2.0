from math import inf
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
    import heapq
    dist = {node: float('inf') for node in graph}
    prev = {node: None for node in graph}
    dist[source] = 0
    pq = [(0, source)]
    while pq:
        current_dist, u = heapq.heappop(pq)
        if current_dist > dist[u]: continue
        for v, weight in graph[u].items():
            distance = current_dist + weight
            if distance < dist[v]:
                dist[v] = distance
                prev[v] = u
                heapq.heappush(pq, (distance, v))
    return dist, prev


def bellman_ford(graph, source):
    dist = {node: float('inf') for node in graph}
    prev = {node: None for node in graph}
    dist[source] = 0
    nodes = list(graph.keys())
    
    for _ in range(len(nodes) - 1):
        for u in graph:
            for v, weight in graph[u].items():
                if dist[u] != inf and dist[u] + weight < dist[v]:
                    dist[v] = dist[u] + weight
                    prev[v] = u
    return dist, prev

def reconstruct_path(prev, src, dst):
    if prev[dst] is None and dst != src: return None
    path = [dst]
    cur = dst
    while cur != src:
        cur = prev[cur]
        if cur is None: return None
        path.append(cur)
    path.reverse()
    return path

def print_spt(graph, root):
    # Sử dụng Bellman-Ford thay vì Dijkstra ở đây
    dist, prev = bellman_ford(graph, root)
    print(f"===== CÂY ĐƯỜNG ĐI NGẮN NHẤT (BELLMAN-FORD) TỪ {root} =====")
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
    ip_map = {}
    mac_map = {}
    for i, name in enumerate(sorted(nodes), start=1):
        ip_map[name] = f"10.0.0.{i}"
        last_octet = i & 0xFF
        mac_map[name] = f"00:00:5e:00:00:{last_octet:02x}"
    return ip_map, mac_map

def ip_to_net24(ip):
    parts = ip.split(".")
    parts[-1] = "0"
    return ".".join(parts)


class RIPRouter:
    def __init__(self, name, neighbors):
        self.name = name
        self.neighbors = neighbors
        self.table = {}
        self.init_table()

    def init_table(self):
        self.table[self.name] = (0, self.name)
        for nb, c in self.neighbors.items():
            self.table[nb] = (c, nb)

    def prepare_update(self):
        return {dst: cost for dst, (cost, _) in self.table.items()}

    def recv_update(self, from_nb, vector):
        changed = False
        cost_to_nb = self.neighbors[from_nb]
        for dest, their_cost in vector.items():
            if their_cost == inf: continue
            new_cost = cost_to_nb + their_cost
            if (dest not in self.table) or (new_cost < self.table[dest][0]):
                self.table[dest] = (new_cost, from_nb)
                changed = True
        return changed

def build_rip_response(routes):
    header = struct.pack("!BBH", 2, 2, 0)
    entries = b""
    for ip, mask, metric in routes:
        # Dùng signed int 'i' để Wireshark decode được số âm
        entries += struct.pack("!HH4s4s4si", 2, 0, socket.inet_aton(ip), 
                               socket.inet_aton(mask), socket.inet_aton("0.0.0.0"), int(metric))
    return header + entries

def simulate_rip_with_pcap(graph, ip_map, mac_map, max_rounds=10):
    # Không dùng make_undirected ở đây để giữ tính chất đồ thị có hướng cho cạnh âm
    routers = {name: RIPRouter(name, graph[name]) for name in graph}
    pcap_packets = []
    rip_multicast_ip = "224.0.0.9"
    rip_multicast_mac = "01:00:5e:00:00:09"

    for rnd in range(max_rounds):
        messages = []
        any_change = False
        for name, rtr in routers.items():
            vec = rtr.prepare_update()
            for nb in rtr.neighbors:
                messages.append((nb, name, vec))
            
            routes = []
            for dest, cost in vec.items():
                if cost == inf: continue
                net = ip_to_net24(ip_map[dest])
                routes.append((net, "255.255.255.0", int(cost)))
            
            if routes:
                payload = build_rip_response(routes)
                pkt = Ether(src=mac_map[name], dst=rip_multicast_mac) / \
                      IP(src=ip_map[name], dst=rip_multicast_ip) / \
                      UDP(sport=520, dport=520) / Raw(payload)
                pcap_packets.append(pkt)

        for dst, src, vec in messages:
            changed = routers[dst].recv_update(src, vec)
            any_change = any_change or changed
        if not any_change: break

    return routers, pcap_packets



class OSPFRouter:
    def __init__(self, name, neighbors):
        self.name = name
        self.neighbors = neighbors
        self.lsdb = {self.name: dict(self.neighbors)}
        self.table = {}

    def originate_lsa(self):
        return self.name, dict(self.neighbors)

    def recv_lsa(self, origin, adj):
        old = self.lsdb.get(origin)
        if old is None or old != adj:
            self.lsdb[origin] = dict(adj)
            return True
        return False

    def compute_shortest_paths(self):
        # THAY ĐỔI: Dùng Bellman-Ford thay vì Dijkstra trong LSDB
        dist, prev = bellman_ford(self.lsdb, self.name)
        self.table = build_routing_table(self.name, dist, prev)

def build_routing_table(source, dist, prev):
    table = {}
    for dest, d in dist.items():
        if d == inf: continue
        if dest == source:
            table[dest] = (0, source)
            continue
        nh = dest
        while prev[nh] is not None and prev[nh] != source:
            nh = prev[nh]
        if prev[nh] is None: continue
        table[dest] = (d, nh)
    return table

def build_ospf_hello(router_id, area_id="0.0.0.0", neighbors=None):
    if neighbors is None: neighbors = []
    rid_bytes = socket.inet_aton(router_id)
    area_bytes = socket.inet_aton(area_id)
    body = socket.inet_aton("255.255.255.0") + struct.pack("!HBBI", 10, 0x02, 1, 40) + \
           rid_bytes + socket.inet_aton("0.0.0.0")
    for nid in neighbors: body += socket.inet_aton(nid)
    header = struct.pack("!BBH4s4sHH8s", 2, 1, 24 + len(body), rid_bytes, area_bytes, 0, 0, b"\x00"*8)
    return header + body

def simulate_ospf_with_pcap(graph, ip_map, mac_map, max_rounds=5):
    routers = {name: OSPFRouter(name, graph[name]) for name in graph}
    pcap_packets = []
    for rnd in range(max_rounds):
        messages = []
        any_change = False
        for name, rtr in routers.items():
            origin, adj = rtr.originate_lsa()
            for nb in rtr.neighbors:
                messages.append((nb, origin, adj))
            hello = build_ospf_hello(ip_map[name], neighbors=[ip_map[nb] for nb in rtr.neighbors])
            pkt = Ether(src=mac_map[name], dst="01:00:5e:00:00:05") / \
                  IP(src=ip_map[name], dst="224.0.0.5", proto=89) / Raw(hello)
            pcap_packets.append(pkt)
        for dst, origin, adj in messages:
            changed = routers[dst].recv_lsa(origin, adj)
            any_change = any_change or changed
        if not any_change: break
    for rtr in routers.values():
        rtr.compute_shortest_paths()
    return routers, pcap_packets

def print_routing_table(label, table):
    print(f"--- Bảng định tuyến tại {label} ---")
    for dest, (cost, nh) in sorted(table.items()):
        print(f"  đích {dest:>3}  | cost = {cost:>2}  | next-hop = {nh}")
    print()



def main():
    graph = {
        "R1": {"R2": 4, "R3": 4, "R8": 8},
        "R2": {"R1": 4, "R4": 3, "R5": 10},
        "R3": {"R1": 4, "R4": -5, "R6": 6}, # Cạnh âm 1
        "R4": {"R2": 3, "R5": 2, "R6": 1},
        "R5": {"R2": 10, "R4": 2, "R7": -3, "R8": 5}, # Cạnh âm 2
        "R6": {"R3": 6, "R4": 1, "R7": 4, "R2": -2}, # Cạnh âm 3
        "R7": {"R5": 5, "R6": 4, "R8": 2},
        "R8": {"R1": 8, "R5": 5, "R7": 2},
    }

    ip_map, mac_map = assign_addresses(graph.keys())

    # 1. Chạy RIP (Bellman-Ford / Distance Vector)
    rip_routers, rip_pkts = simulate_rip_with_pcap(graph, ip_map, mac_map)
    print("===== KẾT QUẢ RIP (BELLMAN-FORD) =====")
    for name, rtr in rip_routers.items():
        print_routing_table(name, rtr.table)

    # 2. Chạy OSPF (Bellman-Ford / Link State)
    ospf_routers, ospf_pkts = simulate_ospf_with_pcap(graph, ip_map, mac_map)
    print("===== KẾT QUẢ OSPF (LINK STATE + BF) =====")
    for name, rtr in ospf_routers.items():
        print_routing_table(name, rtr.table)

    # 3. In SPT từ R1
    print_spt(graph, root="R1")

    # 4. Gộp gói tin và xuất file PCAP
    all_pkts = rip_pkts + ospf_pkts
    t = 0.0
    for p in all_pkts:
        p.time = t
        t += 0.05

    folder_name = "ET4070_Project"

    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    file_path = os.path.join(folder_name, "routing_bellman_ford_testv1.pcap")
    
    wrpcap(file_path, all_pkts)
    print(f"--- Đã lưu file thành công tại: {file_path} ---")

if __name__ == "__main__":
    main()