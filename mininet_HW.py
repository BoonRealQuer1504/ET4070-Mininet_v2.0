import argparse, os, time, re, threading, subprocess
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

from threading import Lock
cmd_lock = Lock()
# ---------- Utils ----------
def apply_netem(node, iface, rate_mbps, delay_ms, limit_pkts):
    node.cmd(f"tc qdisc del dev {iface} root 2>/dev/null")
    node.cmd(
        f"tc qdisc replace dev {iface} root netem "
        f"rate {rate_mbps}mbit delay {delay_ms}ms limit {limit_pkts}"
    )

def monitor_qdisc(node, iface, out_csv, duration, interval=0.2):
    import csv, time
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["t","backlog_bytes","backlog_pkts","dropped_total"])
        t0 = time.time()
        while time.time() - t0 < duration:
            with cmd_lock: 
                s = node.cmd(f"tc -s qdisc show dev {iface}")
            m_back = re.search(r"backlog\s+(\d+)b\s+(\d+)p", s)
            m_drop = re.search(r"\(dropped\s+(\d+),", s)
            bb = int(m_back.group(1)) if m_back else 0
            bp = int(m_back.group(2)) if m_back else 0
            dr = int(m_drop.group(1)) if m_drop else 0
            w.writerow([f"{time.time()-t0:.6f}", bb, bp, dr]); f.flush()
            time.sleep(interval)

def add_flow(sw, rule):
    return sw.cmd(f'ovs-ofctl -O OpenFlow13 add-flow {sw.name} "{rule}"')

def add_group_select(sw, gid, buckets, selection="dp_hash"):
    # try weighted buckets
    btxt = ",".join([f"bucket=weight:{w},actions=output:{p}" for w,p in buckets])
    cmd = (f'ovs-ofctl -O OpenFlow13 add-group {sw.name} '
           f'"group_id={gid},type=select,selection_method={selection},{btxt}"')
    out = sw.cmd(cmd)
    if "syntax error" in out or "unknown" in out:
        rep = []
        for w,p in buckets:
            k = max(1, int(round(w*10)))
            rep += [f"bucket=actions=output:{p}"]*k
        btxt = ",".join(rep)
        cmd = (f'ovs-ofctl -O OpenFlow13 add-group {sw.name} '
               f'"group_id={gid},type=select,selection_method={selection},{btxt}"')
        out2 = sw.cmd(cmd); return out2
    return out

def choose_sender_script(script_dir):
    cand = os.path.join(script_dir, "poisson_sender.py")
    if os.path.isfile(cand):
        return cand, "poisson"
    raise FileNotFoundError("Not found poisson_sender.py.")

# ---------- Main ----------
def run():
    setLogLevel('info')
    ap = argparse.ArgumentParser()
    
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--size", type=int, default=256)
    ap.add_argument("--mode", choices=["poisson","cbr"], default="poisson")
    ap.add_argument("--lam", type=str, default="400,250,180", help="λ cho 3 flow (pkt/s)")
    ap.add_argument("--pps", type=str, default="", help="pps cho 3 flow")
    ap.add_argument("--bitrate-mbps", type=float, default=0.0, help="Bitrate theo Mbps")
    ap.add_argument("--include-ip-udp", action="store_true")
    # Xác suất lưu lượng s1 sang node khác
    ap.add_argument("--p_s2_s3", type=float, default=0.6, help="P(s2->s3)")
    ap.add_argument("--p_s2_s4", type=float, default=0.4, help="P(s2->s4)")
    ap.add_argument("--p_s3_s5", type=float, default=0.6, help="P(s3->s5)")
    ap.add_argument("--p_s3_s6", type=float, default=0.4, help="P(s3->s6)")
    ap.add_argument("--rate", type=float, default=5.0)
    ap.add_argument("--queue", type=int, default=60)
    ap.add_argument("--delay", type=float, default=10.0)
    # Cấu hình từng lưu lượng khác
    ap.add_argument("--r_s1_s3", type=float, default=None); ap.add_argument("--q_s1_s3", type=int, default=None); ap.add_argument("--d_s1_s3", type=float, default=None)
    ap.add_argument("--r_s2_s4", type=float, default=None); ap.add_argument("--q_s2_s4", type=int, default=None); ap.add_argument("--d_s2_s4", type=float, default=None)
    ap.add_argument("--r_s2_s3", type=float, default=None); ap.add_argument("--q_s2_s3", type=int, default=None); ap.add_argument("--d_s2_s3", type=float, default=None)
    ap.add_argument("--r_s3_s6", type=float, default=None); ap.add_argument("--q_s3_s6", type=int, default=None); ap.add_argument("--d_s3_s6", type=float, default=None)
    ap.add_argument("--r_s3_s5", type=float, default=None); ap.add_argument("--q_s3_s5", type=int, default=None); ap.add_argument("--d_s3_s5", type=float, default=None)
    ap.add_argument("--r_s4_s6", type=float, default=None); ap.add_argument("--q_s4_s6", type=int, default=None); ap.add_argument("--d_s4_s6", type=float, default=None)
    ap.add_argument("--r_s5_h4", type=float, default=None); ap.add_argument("--q_s5_h4", type=int, default=None); ap.add_argument("--d_s5_h4", type=float, default=None)
    ap.add_argument("--r_s6_h5", type=float, default=None); ap.add_argument("--q_s6_h5", type=int, default=None); ap.add_argument("--d_s6_h5", type=float, default=None)
    # Kết quả
    ap.add_argument("--results", default="results")
    args = ap.parse_args()

    
    resdir = args.results
    os.makedirs(resdir, exist_ok=True)
    info(f"*** Results dir: {resdir}\n")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    recv_py = os.path.join(script_dir, "udp_receiver.py")
    snd_py, snd_kind = choose_sender_script(script_dir)
    if not os.path.isfile(recv_py):
        raise FileNotFoundError("Not found udp_receiver.py")

    # ---------- Topology ----------
    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink)

    # Hosts
    h1 = net.addHost('h1', ip='10.0.0.11/24')
    h2 = net.addHost('h2', ip='10.0.0.12/24')
    h3 = net.addHost('h3', ip='10.0.0.13/24')
    h4 = net.addHost('h4', ip='10.0.0.21/24')
    h5 = net.addHost('h5', ip='10.0.0.22/24')

    # Switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13', failMode='secure')
    s2 = net.addSwitch('s2', protocols='OpenFlow13', failMode='secure')
    s3 = net.addSwitch('s3', protocols='OpenFlow13', failMode='secure')
    s4 = net.addSwitch('s4', protocols='OpenFlow13', failMode='secure')
    s5 = net.addSwitch('s5', protocols='OpenFlow13', failMode='secure')
    s6 = net.addSwitch('s6', protocols='OpenFlow13', failMode='secure')

    # Links
    net.addLink(h1, s1)         
    net.addLink(h2, s1)          
    net.addLink(h3, s2)          
    net.addLink(s1, s3)          
    net.addLink(s2, s4)          
    net.addLink(s2, s3)         
    net.addLink(s3, s5)          
    net.addLink(s4, s6)          
    net.addLink(s3, s6)          
    net.addLink(s5, h4) 
    net.addLink(s6, h5) 

    net.start()
    info("*** Network started\n")

    h4_mac = h4.MAC(); h5_mac = h5.MAC()
    h1.cmd(f"ip neigh replace 10.0.0.21 lladdr {h4_mac} dev h1-eth0 nud permanent")
    h2.cmd(f"ip neigh replace 10.0.0.22 lladdr {h5_mac} dev h2-eth0 nud permanent")
    h3.cmd(f"ip neigh replace 10.0.0.21 lladdr {h4_mac} dev h3-eth0 nud permanent")

        # ====================== CẤU HÌNH HÀNG ĐỢI (NETEM) ======================
    info("*** Configuring queueing discipline (netem)...\n")
    def V(val, default): return val if val is not None else default

    # Cấu hình mặc định nếu không chỉ định riêng
    default_rate = args.rate      # 5.0 Mbps
    default_delay = args.delay    # 10 ms
    default_queue = args.queue    # 60 packets

    # Danh sách các interface cần cấu hình (chỉ từ switch → switch/host)
    queue_configs = [
        # từ s1
        ("s1", "s1-eth3", args.r_s1_s3, args.d_s1_s3, args.q_s1_s3),  # s1 → s3
        # từ s2
        ("s2", "s2-eth3", args.r_s2_s3, args.d_s2_s3, args.q_s2_s3),  # s2 → s4
        ("s2", "s2-eth4", args.r_s2_s4, args.d_s2_s4, args.q_s2_s4),  # s2 → s3
        # từ s3
        ("s3", "s3-eth4", args.r_s3_s5, args.d_s3_s5, args.q_s3_s5),  # s3 → s5 → h4
        ("s3", "s3-eth5", args.r_s3_s6, args.d_s3_s6, args.q_s3_s6),  # s3 → s6 → h5
        # từ s4
        ("s4", "s4-eth3", args.r_s4_s6, args.d_s4_s6, args.q_s4_s6),  # s4 → s6
        # ra host
        ("s5", "s5-eth2", args.r_s5_h4, args.d_s5_h4, args.q_s5_h4),  # s5 → h4
        ("s6", "s6-eth2", args.r_s6_h5, args.d_s6_h5, args.q_s6_h5),  # s6 → h5
    ]

    for sw_name, iface, r, d, q in queue_configs:
        sw = locals()[sw_name]
        apply_netem(
            sw, iface,
            V(r, default_rate),
            V(d, default_delay),
            V(q, default_queue)
        )

    # ====================== OPENFLOW RULES + GROUP SELECT ======================
    info("*** Installing OpenFlow rules...\n")

    # Default drop
    for sw in [s1, s2, s3, s4, s5, s6]:
        add_flow(sw, "priority=0,actions=drop")

    # --- s2: chia đường từ h3 (0.3 → s3, 0.7 → s4) ---
    add_group_select(s2, 10, [(args.p_s2_s3, 4), (args.p_s2_s4, 3)])  # port 4=s3, port 3=s4
    add_flow(s2, "priority=100,ip,udp,in_port=1,actions=group:10")   # từ h3

    # --- s3: chia đường (0.6 → s5 → h4, 0.4 → s6 → h5) ---
    add_group_select(s3, 20, [(args.p_s3_s5, 4), (args.p_s3_s6, 5)])  # port 4=s5, port 5=s6
    add_flow(s3, "priority=100,ip,udp,in_port=1,actions=group:20")   # từ s1
    add_flow(s3, "priority=100,ip,udp,in_port=2,actions=group:20")   # từ s2 (nếu có)

    # --- s1: chỉ chuyển tiếp từ h1,h2 → s3 (không chia đường) ---
    add_flow(s1, "priority=100,ip,udp,in_port=1,actions=output:3")   # h1 → s3
    add_flow(s1, "priority=100,ip,udp,in_port=2,actions=output:3")   # h2 → s3

    # --- s4: chỉ chuyển tiếp → s6 ---
    add_flow(s4, "priority=100,ip,udp,actions=output:3")             # → s6

    # --- s5 & s6: ra host ---
    add_flow(s5, "priority=100,ip,udp,actions=output:2")             # → h4
    add_flow(s6, "priority=100,ip,udp,actions=output:2")             # → h5

    # ====================== RECEIVERS ======================
    recvA = os.path.join(resdir, "recv_h4.csv")
    recvB = os.path.join(resdir, "recv_h5.csv")
    port_h4, port_h5 = 5551, 5552

    h4.cmd(f"python3 {recv_py} --port {port_h4} --duration {args.duration+5} --out {recvA} &")
    h5.cmd(f"python3 {recv_py} --port {port_h5} --duration {args.duration+5} --out {recvB} &")

    # ====================== SENDERS (Poisson) ======================
    send_h1 = os.path.join(resdir, "send_h1.csv")
    send_h2 = os.path.join(resdir, "send_h2.csv")
    send_h3 = os.path.join(resdir, "send_h3.csv")

    lam = [float(x) for x in args.lam.split(",")]  # 3 giá trị: h1, h2, h3

    h1.cmd(f"python3 {snd_py} --dst 10.0.0.21 --port {port_h4} --lam {lam[0]} --size {args.size} --duration {args.duration} --out {send_h1} &")
    h2.cmd(f"python3 {snd_py} --dst 10.0.0.21 --port {port_h4} --lam {lam[1]} --size {args.size} --duration {args.duration} --out {send_h2} &")
    h3.cmd(f"python3 {snd_py} --dst 10.0.0.22 --port {port_h5} --lam {lam[2]} --size {args.size} --duration {args.duration} --out {send_h3} &")

    # ====================== MONITOR QUEUE ======================
    mons = [
        ("s1","s1-eth3","queue_s1_s3.csv"),
        ("s2","s2-eth3","queue_s2_s4.csv"),
        ("s2","s2-eth4","queue_s2_s3.csv"),
        ("s3","s3-eth4","queue_s3_s5.csv"),
        ("s3","s3-eth5","queue_s3_s6.csv"),
        ("s4","s4-eth3","queue_s4_s6.csv"),
        ("s5","s5-eth2","queue_s5_h4.csv"),
        ("s6","s6-eth2","queue_s6_h5.csv"),
    ]
    threads = []
    for sw_name, iface, fname in mons:
        sw = locals()[sw_name]
        csv_path = os.path.join(resdir, fname)
        t = threading.Thread(target=monitor_qdisc, args=(sw, iface, csv_path, args.duration+10))
        t.daemon = True
        t.start()
        threads.append(t)

    # ====================== CHẠY & KẾT THÚC ======================
    info(f"*** Running experiment for {args.duration}s...\n")
    time.sleep(args.duration + 10)

    net.stop()
    info("*** Done!\n")
    print("\n" + "="*50)
    print("KẾT QUẢ ĐÃ LƯU TẠI:", resdir)
    print(f" • Gửi từ h1,h2 → h4: {send_h1}, {send_h2}")
    print(f" • Gửi từ h3 → h5: {send_h3}")
    print(f" • Nhận h4: {recvA}")
    print(f" • Nhận h5: {recvB}")
    print(" • Queue logs: queue_*.csv")
    print("="*50)

if __name__ == "__main__":
    run()