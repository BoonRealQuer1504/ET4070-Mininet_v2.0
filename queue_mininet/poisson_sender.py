import argparse, socket, time, random, struct, os, csv

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", default="10.0.0.2")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--lam", type=float, default=300.0, help="Poisson rate λ (packets/s)")
    ap.add_argument("--duration", type=float, default=20.0, help="seconds")
    ap.add_argument("--size", type=int, default=256, help="UDP payload bytes (>=12)")
    ap.add_argument("--out", default="/tmp/send_log.csv")
    args = ap.parse_args()

    assert args.size >= 12, "payload size must be >= 12 bytes (timestamp+seq)"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (args.dst, args.port)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    f = open(args.out, "w", newline="")
    w = csv.writer(f)
    w.writerow(["t_send", "seq", "bytes"])

    seq = 0
    t0 = time.time()
    next_t = t0
    end_t = t0 + args.duration

    try:
        while True:
            next_t += random.expovariate(args.lam)
            now = time.time()
            if next_t > end_t: break
            dt = next_t - now
            if dt > 0:
                time.sleep(dt)

            seq += 1
            t_send = time.time()
            hdr = struct.pack("!dI", t_send, seq)  # 8B timestamp + 4B seq
            pad_len = max(0, args.size - len(hdr))
            payload = hdr + (b'\x00' * pad_len)
            sock.sendto(payload, dst)
            w.writerow([f"{t_send:.6f}", seq, args.size])
            f.flush()
    finally:
        f.close()

if __name__ == "__main__":
    main()