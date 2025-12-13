import argparse
import os
import time
import re
import threading
import subprocess
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def sh(cmd: str) -> int:
    return subprocess.call(cmd, shell=True)


def monitor_qdisc(node, iface, out_csv, duration, interval=0.2):
    import csv
    start = time.time()
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "backlog_bytes", "backlog_pkts", "dropped_total"])
        while time.time() - start < duration:
            s = node.cmd(f"tc -s qdisc show dev {iface}")
            m_back = re.search(r"backlog\s+(\d+)b\s+(\d+)p", s)
            m_drop = re.search(r"\(dropped\s+(\d+),", s)

            bb = int(m_back.group(1)) if m_back else 0
            bp = int(m_back.group(2)) if m_back else 0
            dr = int(m_drop.group(1)) if m_drop else 0

            w.writerow([f"{time.time():.6f}", bb, bp, dr])
            f.flush()
            time.sleep(interval)


def apply_netem(sw, iface, rate_mbps, delay_ms, limit_pkts):
    """Xóa và áp qdisc netem lên iface."""
    sw.cmd(f"tc qdisc del dev {iface} root 2>/dev/null")
    sw.cmd(
        f"tc qdisc replace dev {iface} root netem "
        f"rate {rate_mbps}mbit limit {limit_pkts} delay {delay_ms}ms"
    )


def run():
    setLogLevel('info')

    ap = argparse.ArgumentParser(description="Mininet queueing network: h1-s1-s2-h2")
    
    ap.add_argument("--lam", type=float, default=300.0, help="Poisson λ (pkt/s)")
    ap.add_argument("--duration", type=float, default=20.0, help="Thời gian phát (s)")
    ap.add_argument("--pkt-size", type=int, default=256, help="UDP payload (bytes)")
    ap.add_argument("--port", type=int, default=5555, help="UDP port")
    
    ap.add_argument("--rate-limit-mbps", type=float, default=5.0, help="Rate mặc định (Mbit/s)")
    ap.add_argument("--queue-pkts", type=int, default=50, help="Queue limit mặc định (pkts)")
    ap.add_argument("--delay-ms", type=float, default=10.0, help="Delay mặc định (ms)")
    
    ap.add_argument("--rate12-mbps", type=float, default=None, help="Rate hop s1->s2 (Mbit/s)")
    ap.add_argument("--queue12-pkts", type=int, default=None, help="Queue hop s1->s2 (pkts)")
    ap.add_argument("--delay12-ms", type=float, default=None, help="Delay hop s1->s2 (ms)")
    ap.add_argument("--rate23-mbps", type=float, default=None, help="Rate hop s2->h2 (Mbit/s)")
    ap.add_argument("--queue23-pkts", type=int, default=None, help="Queue hop s2->h2 (pkts)")
    ap.add_argument("--delay23-ms", type=float, default=None, help="Delay hop s2->h2 (ms)")

    ap.add_argument("--results", default="results", help="Thư mục kết quả")
    args = ap.parse_args()

    resdir = args.results
    os.makedirs(resdir, exist_ok=True)
    info(f"*** Results dir: {resdir}\n")

    # sender/receiver scripts
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sender_py = os.path.join(script_dir, "poisson_sender.py")   # hoặc sender.py (CBR/Poisson)
    receiver_py = os.path.join(script_dir, "udp_receiver.py")

    for p in (sender_py, receiver_py):
        if not os.path.isfile(p):
            raise FileNotFoundError(f"Không tìm thấy file: {p}")

    # ===== Topo: h1 -- s1 -- s2 -- h2 (OVSBridge, no controller) =====
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    net.addLink(h1, s1)   # h1-eth0 <-> s1-eth1
    net.addLink(s1, s2)   # s1-eth2 <-> s2-eth1
    net.addLink(s2, h2)   # s2-eth2 <-> h2-eth0

    net.start()
    info("*** Network started (bridge mode, no controller)\n")
    

    # Kiểm tra kết nối
    ping_out = h1.cmd("ping -c1 -W 1 10.0.0.2")
    info("*** Ping test h1->h2:\n" + ping_out + "\n")

    # ===== netem trên hai hop theo chiều h1->h2 =====
    # Hop 1: s1 -> s2 (egress s1-eth2)
    rate12 = args.rate12_mbps if args.rate12_mbps is not None else args.rate_limit_mbps
    q12    = args.queue12_pkts if args.queue12_pkts is not None else args.queue_pkts
    d12    = args.delay12_ms   if args.delay12_ms   is not None else args.delay_ms
    apply_netem(s1, "s1-eth2", rate12, d12, q12)
    info(f"*** Netem s1-eth2: rate {rate12}M, limit {q12} pkts, delay {d12}ms\n")

    # Hop 2: s2 -> h2 (egress s2-eth2)
    rate23 = args.rate23_mbps if args.rate23_mbps is not None else args.rate_limit_mbps
    q23    = args.queue23_pkts if args.queue23_pkts is not None else args.queue_pkts
    d23    = args.delay23_ms   if args.delay23_ms   is not None else args.delay_ms
    apply_netem(s2, "s2-eth2", rate23, d23, q23)
    info(f"*** Netem s2-eth2: rate {rate23}M, limit {q23} pkts, delay {d23}ms\n")

    # ===== Sniff tại h2 =====
    pcap = os.path.join(resdir, "sniff.pcap")
    h2.cmd(f"tcpdump -i h2-eth0 -w {pcap} udp port {args.port} &")
    info(f"*** tcpdump started at {pcap}\n")

    # ===== Logs =====
    recv_csv = os.path.join(resdir, "recv_log.csv")
    send_csv = os.path.join(resdir, "send_log.csv")
    q1_csv   = os.path.join(resdir, "queue_s1_eth2.csv")
    q2_csv   = os.path.join(resdir, "queue_s2_eth2.csv")

    h2.cmd(
        f"python3 {receiver_py} --port {args.port} "
        f"--duration {args.duration + 2} --out {recv_csv} &"
    )

    h1.cmd(
        f"python3 {sender_py} --dst 10.0.0.2 --port {args.port} "
        f"--lam {args.lam} --duration {args.duration} "
        f"--size {args.pkt_size} --out {send_csv} &"
    )

    mon1 = threading.Thread(
        target=monitor_qdisc,
        args=(s1, "s1-eth2", q1_csv, args.duration + 2),
        kwargs=dict(interval=0.2),
        daemon=True
    )
    mon2 = threading.Thread(
        target=monitor_qdisc,
        args=(s2, "s2-eth2", q2_csv, args.duration + 2),
        kwargs=dict(interval=0.2),
        daemon=True
    )
    mon1.start(); mon2.start()

    time.sleep(args.duration + 3)

    h2.cmd("pkill -f tcpdump")
    info("*** tcpdump stopped\n")
    net.stop()
    info("*** Network stopped\n")

if __name__ == "__main__":
    run()
 