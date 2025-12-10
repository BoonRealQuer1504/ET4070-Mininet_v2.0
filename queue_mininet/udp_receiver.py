import argparse, socket, time, struct, os, csv

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--duration", type=float, default=22.0)
    ap.add_argument("--out", default="/tmp/recv_log.csv")
    ap.add_argument("--buf", type=int, default=4*1024*1024)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    f = open(args.out, "w", newline="")
    w = csv.writer(f)
    w.writerow(["t_recv", "seq", "bytes", "t_send", "latency_ms"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.buf)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(1.0)

    end_t = time.time() + args.duration
    try:
        while time.time() < end_t:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            t_recv = time.time()
            if len(data) < 12:  # d + I
                continue
            t_send, seq = struct.unpack("!dI", data[:12])
            latency_ms = (t_recv - t_send) * 1000.0
            w.writerow([f"{t_recv:.6f}", seq, len(data), f"{t_send:.6f}", f"{latency_ms:.3f}"])
            f.flush()
    finally:
        f.close()

if __name__ == "__main__":
    main()
