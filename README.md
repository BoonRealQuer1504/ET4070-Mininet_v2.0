# Chạy mô phỏng Mininet

- Dựng topo h1 -- s1 -- h2 (bridge L2, không cần controller)
- Bóp băng thông/độ trễ + giới hạn hàng đợi trên cổng nghẽn bằng `tc netem`
- Chạy receiver (h2) + sender Poisson (h1)
- Sniff gói bằng tcpdump tại h2
- Theo dõi backlog/dropped từ qdisc để vẽ/ phân tích sau

Mẫu dòng lệnh chạy:

```bash
sudo python3 run_mininet_poisson.py --lam 300 --duration 20 --pkt-size 256 --rate-limit-mbps 5 --queue-pkts 50 --delay-ms 10
```

Chi tiết về các tham số cấu hình:
- `--lam`: Poisson rate λ (pkt/s)
- `--duration`: Thời gian phát (s)
- `--pkt-size`: Kích thước payload UDP (bytes)
- `--rate-limit-mbps`: Bottleneck rate (Mbit/s)
- `--queue-pkts`: Giới hạn hàng đợi (packets)
- `--delay-ms`: Độ trễ bổ sung tại nút nghẽn (ms)
- `--port`: Port được dùng
- `--results`: Thư mục chứa kết quả