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


def monitor_qdisc(switch, iface, out_csv, duration, interval=0.2):
    """
    Ghi log backlog (bytes, pkts) và dropped từ `tc -s qdisc show dev <iface>`
    vào CSV theo chu kỳ interval (s).
    """
    import csv
    start = time.time()
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "backlog_bytes", "backlog_pkts", "dropped_total"])
        while time.time() - start < duration:
            s = switch.cmd(f"tc -s qdisc show dev {iface}")
            m_back = re.search(r"backlog\s+(\d+)b\s+(\d+)p", s)
            m_drop = re.search(r"\(dropped\s+(\d+),", s)

            bb = int(m_back.group(1)) if m_back else 0
            bp = int(m_back.group(2)) if m_back else 0
            dr = int(m_drop.group(1)) if m_drop else 0

            w.writerow([f"{time.time():.6f}", bb, bp, dr])
            f.flush()
            time.sleep(interval)


def run():
    setLogLevel('info')

    ap = argparse.ArgumentParser(description="Mininet simulation")
    ap.add_argument("--lam", type=float, default=300.0, help="Poisson rate λ (pkt/s)")
    ap.add_argument("--duration", type=float, default=20.0, help="Thời gian phát (s)")
    ap.add_argument("--pkt-size", type=int, default=256, help="Kích thước payload UDP (bytes)")
    ap.add_argument("--rate-limit-mbps", type=float, default=5.0, help="Bottleneck rate (Mbit/s)")
    ap.add_argument("--queue-pkts", type=int, default=50, help="Giới hạn hàng đợi (packets)")
    ap.add_argument("--delay-ms", type=float, default=10.0, help="Độ trễ bổ sung tại nút nghẽn (ms)")
    ap.add_argument("--port", type=int, default=5555, help="Port được dùng")
    ap.add_argument("--results", default="results", help="Thư mục chứa kết quả")
    args = ap.parse_args()

    resdir = args.results
    info(f"*** Results dir: {resdir}\n")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    sender_py = os.path.join(script_dir, "poisson_sender.py")
    receiver_py = os.path.join(script_dir, "udp_receiver.py")

    for p in (sender_py, receiver_py):
        if not os.path.isfile(p):
            raise FileNotFoundError(f"Không tìm thấy file: {p}")

    # Dựng mạng bằng Mininet
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)

    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    s1 = net.addSwitch('s1')    # OVSBridge

    # Dựng link như topo được dựng
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    net.start()
    info("*** Network started (bridge mode, no controller)\n")

    # Ping kiểm tra kết nối
    ping_out = h1.cmd("ping -c1 -W 1 10.0.0.2")
    info("*** Ping test h1->h2:\n" + ping_out + "\n")

    # Áp qdisc netem trên cổng s1-eth2 (nhánh về h2)
    bottleneck = "s1-eth2"
    rate = args.rate_limit_mbps
    delay = args.delay_ms
    qpkts = args.queue_pkts

    # Xóa qdisc cũ (nếu có) rồi áp mới
    s1.cmd(f"tc qdisc del dev {bottleneck} root 2>/dev/null")
    # netem với rate + delay + limit (số packet trong hàng đợi)
    s1.cmd(
        f"tc qdisc replace dev {bottleneck} root netem "
        f"rate {rate}mbit limit {qpkts} delay {delay}ms"
    )
    info(f"*** Applied netem on {bottleneck}: {rate}Mbit, limit {qpkts} pkts, delay {delay}ms\n")

    # Bắt gói tại h2 -> ra file pcap
    pcap = os.path.join(resdir, "sniff.pcap")
    h2.cmd(f"tcpdump -i h2-eth0 -w {pcap} udp port {args.port} &")
    info(f"*** tcpdump started at {pcap}\n")

    # Đường dẫn log
    recv_csv = os.path.join(resdir, "recv_log.csv")
    send_csv = os.path.join(resdir, "send_log.csv")
    q_csv = os.path.join(resdir, "queue_log.csv")

    # Chạy receiver trước
    h2.cmd(
        f"python3 {receiver_py} --port {args.port} "
        f"--duration {args.duration + 2} --out {recv_csv} &"
    )

    # Chạy sender, gói tin theo Poisson
    h1.cmd(
        f"python3 {sender_py} --dst 10.0.0.2 --port {args.port} "
        f"--lam {args.lam} --duration {args.duration} "
        f"--size {args.pkt_size} --out {send_csv} &"
    )

    # Start ...
    mon = threading.Thread(
        target=monitor_qdisc,
        args=(s1, bottleneck, q_csv, args.duration + 2),
        kwargs=dict(interval=0.2),
        daemon=True
    )
    mon.start()

    time.sleep(args.duration + 3)

    # Dừng tcpdump
    h2.cmd("pkill -f tcpdump")
    info("*** tcpdump stopped\n")

    # Dừng mạng
    net.stop()
    info("*** Network stopped\n")

    print("\n=== DONE ===")
    print(f"Send log : {send_csv}")
    print(f"Recv log : {recv_csv}")
    print(f"Queue log: {q_csv}")
    print(f"PCAP     : {pcap}")
    print("\nTiếp theo phân tích:")
    print(f"python3 analyze_results.py --dir {resdir}")


if __name__ == "__main__":
    run()