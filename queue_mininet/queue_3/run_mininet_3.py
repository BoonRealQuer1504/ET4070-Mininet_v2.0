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
            w.writerow([f"{time.time()-t0:.6f}", bb, bp, dr]); 
            f.flush()
            time.sleep(interval)

def add_flow(sw, rule):
    return sw.cmd(f'ovs-ofctl -O OpenFlow13 add-flow {sw.name} "{rule}"')

def add_group_select(sw, gid, buckets, selection="dp_hash"):
    rep = []
    for w,p in buckets:
        k = max(1, int(round(w * 10)))
        rep += [f"bucket=actions=output:{p}"] * k

    btxt = ",".join(rep)
    cmd = (f'ovs-ofctl -O OpenFlow13 add-group {sw.name} '
           f'"group_id={gid},type=select,{btxt}"')

    out = sw.cmd(cmd)
    print("ADD-GROUP:", out)
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
    ap.add_argument("--p_s1_s3", type=float, default=0.6, help="P(s1->s3)")
    ap.add_argument("--p_s1_s4", type=float, default=0.4, help="P(s1->s4)")
    
    ap.add_argument("--rate", type=float, default=5.0)
    ap.add_argument("--queue", type=int, default=60)
    ap.add_argument("--delay", type=float, default=10.0)
    # Cấu hình từng lưu lượng khác
    ap.add_argument("--r_s1_s3", type=float, default=None); ap.add_argument("--q_s1_s3", type=int, default=None); ap.add_argument("--d_s1_s3", type=float, default=None)
    ap.add_argument("--r_s1_s4", type=float, default=None); ap.add_argument("--q_s1_s4", type=int, default=None); ap.add_argument("--d_s1_s4", type=float, default=None)
    ap.add_argument("--r_s2_s3", type=float, default=None); ap.add_argument("--q_s2_s3", type=int, default=None); ap.add_argument("--d_s2_s3", type=float, default=None)
    ap.add_argument("--r_s3_s4", type=float, default=None); ap.add_argument("--q_s3_s4", type=int, default=None); ap.add_argument("--d_s3_s4", type=float, default=None)
    ap.add_argument("--r_s3_h5", type=float, default=None); ap.add_argument("--q_s3_h5", type=int, default=None); ap.add_argument("--d_s3_h5", type=float, default=None)
    ap.add_argument("--r_s4_h4", type=float, default=None); ap.add_argument("--q_s4_h4", type=int, default=None); ap.add_argument("--d_s4_h4", type=float, default=None)
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

    # Links
    net.addLink(h1, s1)          # s1-eth1
    net.addLink(h2, s2)          # s2-eth1
    net.addLink(h3, s2)          # s2-eth2
    net.addLink(s1, s3)          # s1-eth2 <-> s3-eth1
    net.addLink(s1, s4)          # s1-eth3 <-> s4-eth1
    net.addLink(s2, s3)          # s2-eth3 <-> s3-eth2
    net.addLink(s3, s4)          # s3-eth3 <-> s4-eth2
    net.addLink(s4, h4)          # s4-eth3
    net.addLink(s3, h5)          # s3-eth4

    net.start()
    info("*** Network started\n")
    
    

    h4_mac = h4.MAC(); h5_mac = h5.MAC()
    h1.cmd(f"ip neigh replace 10.0.0.21 lladdr {h4_mac} dev h1-eth0 nud permanent")
    h2.cmd(f"ip neigh replace 10.0.0.22 lladdr {h5_mac} dev h2-eth0 nud permanent")
    h3.cmd(f"ip neigh replace 10.0.0.21 lladdr {h4_mac} dev h3-eth0 nud permanent")

    # ---------- Cấu hình node hàng đợi ----------
    def V(v, d): return v if v is not None else d
    # s1->s3 (s1-eth2), s1->s4 (s1-eth3)
    apply_netem(s1, "s1-eth2", V(args.r_s1_s3,args.rate), V(args.d_s1_s3,args.delay), V(args.q_s1_s3,args.queue))
    apply_netem(s1, "s1-eth3", V(args.r_s1_s4,args.rate), V(args.d_s1_s4,args.delay), V(args.q_s1_s4,args.queue))
    # s2->s3 (s2-eth3)
    apply_netem(s2, "s2-eth3", V(args.r_s2_s3,args.rate), V(args.d_s2_s3,args.delay), V(args.q_s2_s3,args.queue))
    # s3->s4 (s3-eth3), s3->h5 (s3-eth4)
    apply_netem(s3, "s3-eth3", V(args.r_s3_s4,args.rate), V(args.d_s3_s4,args.delay), V(args.q_s3_s4,args.queue))
    apply_netem(s3, "s3-eth4", V(args.r_s3_h5,args.rate), V(args.d_s3_h5,args.delay), V(args.q_s3_h5,args.queue))
    # s4->h4 (s4-eth3)
    apply_netem(s4, "s4-eth3", V(args.r_s4_h4,args.rate), V(args.d_s4_h4,args.delay), V(args.q_s4_h4,args.queue))

    # ---------- OpenFlow rules ----------
    # table-miss drop
    for sw in (s1,s2,s3,s4):
        add_flow(sw, "priority=50,arp,actions=flood")
        add_flow(sw, "priority=0,actions=drop")
        

    # s1: group select (gid=10): s1-eth2 (->s3) với p, s1-eth3 (->s4) với 1-p
    p13, p14 = (args.p_s1_s3)*10, (args.p_s1_s4)*10
    add_group_select(s1, 10, [(p13,2),(p14,3)])
    

    # s1: h1 in_port=1, dst==h4 -> group 10; dst==h5 -> output:2 (qua s3)
    add_flow(s1, "priority=100,ip,udp,in_port=1,nw_dst=10.0.0.21,actions=group:10")
    add_flow(s1, "priority=100,ip,udp,in_port=1,nw_dst=10.0.0.22,actions=output:2")

    # s2: từ h2 (in 1) & h3 (in 2) đi về s3 (out 3) cho cả h4/h5
    add_flow(s2, "priority=100,ip,udp,in_port=1,actions=output:3")
    add_flow(s2, "priority=100,ip,udp,in_port=2,actions=output:3")

    # s3: nếu dst=h4 -> đi s4 (out 3); nếu dst=h5 -> ra host h5 (out 4)
    add_flow(s3, "priority=100,ip,udp,nw_dst=10.0.0.21,actions=output:3")
    add_flow(s3, "priority=100,ip,udp,nw_dst=10.0.0.22,actions=output:4")

    # s4: mọi gói tới h4 -> ra h4 (eth3)
    add_flow(s4, "priority=100,ip,udp,nw_dst=10.0.0.21,actions=output:3")
    from mininet.cli import CLI
    CLI(net)

    # ---------- Sniffer tại h4, h5 ----------
    pcap_h4 = os.path.join(resdir, "sniff_h4.pcap")
    pcap_h5 = os.path.join(resdir, "sniff_h5.pcap")
    h4.cmd(f"tcpdump -i h4-eth0 -w {pcap_h4} udp &")
    h5.cmd(f"tcpdump -i h5-eth0 -w {pcap_h5} udp &")

    # ---------- Receivers ----------
    recvA = os.path.join(resdir, "recv_A_h4.csv")
    recvB = os.path.join(resdir, "recv_B_h5.csv")
    recvC = os.path.join(resdir, "recv_C_h4.csv")
    # port riêng cho mỗi flow
    portA, portB, portC = 5551, 5552, 5553
    h4.cmd(f"python3 {recv_py} --port {portA} --duration {args.duration+2} --out {recvA} &")
    h5.cmd(f"python3 {recv_py} --port {portB} --duration {args.duration+2} --out {recvB} &")
    h4.cmd(f"python3 {recv_py} --port {portC} --duration {args.duration+2} --out {recvC} &")

    # ---------- Senders ----------
    sendA = os.path.join(resdir, "send_A_h1_to_h4.csv")
    sendB = os.path.join(resdir, "send_B_h2_to_h5.csv")
    sendC = os.path.join(resdir, "send_C_h3_to_h4.csv")

    lam = [float(x) for x in args.lam.split(",")] if args.lam else [300,300,300]
    pps = [float(x) for x in args.pps.split(",")] if args.pps else [0,0,0]

    def snd_cmd(dst_ip, port, out_csv, lam_or_pps):
        return f"python3 {snd_py} --dst {dst_ip} --port {port} --lam {lam_or_pps} --size {args.size} --duration {args.duration} --out {out_csv} &"

    h1.cmd(snd_cmd("10.0.0.21", portA, sendA, lam[0] if args.mode=="poisson" else pps[0]))
    h2.cmd(snd_cmd("10.0.0.22", portB, sendB, lam[1] if args.mode=="poisson" else pps[1]))
    h3.cmd(snd_cmd("10.0.0.21", portC, sendC, lam[2] if args.mode=="poisson" else pps[2]))

    # ---------- Monitor ----------
    mons = [
        ("s1","s1-eth2","queue_s1_s3.csv"),
        ("s1","s1-eth3","queue_s1_s4.csv"),
        ("s2","s2-eth3","queue_s2_s3.csv"),
        ("s3","s3-eth3","queue_s3_s4.csv"),
        ("s3","s3-eth4","queue_s3_h5.csv"),
        ("s4","s4-eth3","queue_s4_h4.csv"),
    ]
    threads=[]
    for sw,iface,name in mons:
        node = locals()[sw]
        t = threading.Thread(target=monitor_qdisc, args=(node,iface,os.path.join(resdir,name), args.duration+2), kwargs=dict(interval=0.2), daemon=True)
        t.start(); threads.append(t)

    # ---------- Stop ----------
    time.sleep(args.duration + 3)
    h4.cmd("pkill -f tcpdump"); h5.cmd("pkill -f tcpdump")
    net.stop()

    print("\n=== DONE ===")
    print(f"[Flow A] Send: {sendA}  |  Recv: {recvA}")
    print(f"[Flow B] Send: {sendB}  |  Recv: {recvB}")
    print(f"[Flow C] Send: {sendC}  |  Recv: {recvC}")
    for _,_,name in mons:
        print("Queue:", os.path.join(resdir,name))
    print("PCAP:", pcap_h4, pcap_h5)



if __name__ == "__main__":
    run()