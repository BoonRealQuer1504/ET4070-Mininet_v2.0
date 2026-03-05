# Network Simulation uisng Mininet

## Giới thiệu

Mục tiêu của project là nghiên cứu và thực nghiệm hai chủ đề quan trọng trong mạng máy tính:

1. **Queueing trong mạng (Network Queueing)**
2. **Thuật toán định tuyến (Routing Algorithms)**

Các thí nghiệm được triển khai bằng:

* **Python**
* **Mininet (Network Emulator)**
* **UDP traffic generator**
* **Jupyter Notebook** để phân tích dữ liệu
* **Wireshark / tcpdump** để capture packet

Project cho phép so sánh giữa:

* **mô phỏng lý thuyết (theoretical simulation)**
* **mô phỏng mạng thực tế (network emulation)**

---

## Tổng quan cấu trúc repository

```
ET4070_Project
│
├── Simu_queue.ipynb
│
├── queue_mininet
│   ├── queue_1
│   ├── queue_2
│   ├── queue_3
│   └── queue_HW
│
└── routing
    ├── routing_demo
    └── routing_dijkstra
```

Repository được chia thành **hai phần chính**:

| Phần                     | Mục đích                         |
| ------------------------ | -------------------------------- |
| Queue Simulation         | Mô phỏng lý thuyết hàng đợi      |
| Mininet Queue Experiment | Thí nghiệm queue trong mạng      |
| Routing Experiment       | Thí nghiệm thuật toán định tuyến |

---

## 1. Queue Simulation

File:

```
Simu_queue.ipynb
```

Notebook này mô phỏng **mô hình hàng đợi trong mạng** bằng Python.

Các nội dung chính:

* Sinh **Poisson arrival process**
* Mô phỏng **queue system**
* Tính toán các metric:

| Metric           | Ý nghĩa               |
| ---------------- | --------------------- |
| Arrival rate (λ) | tốc độ đến của packet |
| Queue length     | độ dài hàng đợi       |
| Delay            | độ trễ                |
| Throughput       | thông lượng           |

Mục đích của notebook này là:

* kiểm chứng lý thuyết queue
* so sánh với kết quả thu được từ Mininet

---

## 2. Network Queue Experiments (Mininet)

Thư mục:

```
queue_mininet
```

Phần này mô phỏng **queue trong mạng thật** bằng **Mininet**.

### Cấu trúc

```
queue_mininet
│
├── queue_1
├── queue_2
├── queue_3
└── queue_HW
```

Mỗi thư mục tương ứng với **một kịch bản thí nghiệm khác nhau**.

---

### 2.1 Cấu trúc một experiment

Ví dụ:

```
queue_1
│
├── results
├── analyze_results.ipynb
├── poisson_sender.py
├── udp_receiver.py
├── run_mininet_poisson.py
└── README.md
```

### Thành phần chính

#### 1. poisson_sender.py

Script tạo **traffic generator**.

Các packet được gửi theo **Poisson process**.

Đặc điểm:

```
inter-arrival time ~ exponential distribution
```

Mô hình này thường được dùng để mô phỏng **traffic Internet thực tế**.

---

#### 2. udp_receiver.py

Script nhận packet UDP từ sender.

Chức năng:

* nhận packet
* ghi timestamp
* lưu dữ liệu để phân tích

---

#### 3. run_mininet_poisson.py

Script tạo topology mạng trong **Mininet**.

Topology cơ bản:

```
Sender (h1)
    |
    |
   Switch
    |
    |
Receiver (h2)
```

Script sẽ:

1. tạo host
2. tạo switch
3. kết nối link
4. cấu hình queue
5. chạy sender và receiver

---

#### 4. results

Thư mục chứa dữ liệu thu được từ thí nghiệm.

Ví dụ:

```
delay.csv
packet_log.txt
throughput.csv
```

---

#### 5. analyze_results.ipynb

Notebook phân tích dữ liệu.

Các bước phân tích:

```
đọc dữ liệu
→ xử lý
→ vẽ biểu đồ
→ đánh giá performance
```

Ví dụ các biểu đồ:

* Delay vs Arrival rate
* Queue length vs Time
* Throughput

---

### 2.2 Các kịch bản queue

| Folder   | Mục đích                 |
| -------- | ------------------------ |
| queue_1  | kịch bản queue cơ bản    |
| queue_2  | thay đổi tham số queue   |
| queue_3  | thử nghiệm cấu hình khác |
| queue_HW | thí nghiệm tổng hợp      |

Các thí nghiệm nhằm quan sát:

* congestion
* queue buildup
* packet delay
* packet loss

---

## 3. Routing Experiments

Thư mục:

```
routing
```

Phần này nghiên cứu **cơ chế định tuyến trong mạng**.

Cấu trúc:

```
routing
│
├── routing_demo
│   ├── routing_demo.py
│   └── routing_demo.pcap
│
└── routing_dijkstra
    ├── routing_dijkstra.py
    └── routing_dijkstra.pcap
```

---

### 3.1 routing_demo

Thí nghiệm minh họa **routing cơ bản**.

Script:

```
routing_demo.py
```

Script này:

1. tạo topology mạng
2. cấu hình routing
3. gửi packet giữa host

File:

```
routing_demo.pcap
```

Chứa packet capture để phân tích bằng **Wireshark**.

Các packet có thể thấy:

* ARP
* ICMP
* IP packet

---

### 3.2 routing_dijkstra

Phần này triển khai **thuật toán Dijkstra** để tìm đường đi ngắn nhất.

Script:

```
routing_dijkstra.py
```

Thuật toán Dijkstra được sử dụng để tính:

```
Shortest Path
```

trong network graph.

Trong mô hình mạng:

| Thành phần | Tương ứng    |
| ---------- | ------------ |
| Node       | Router       |
| Edge       | Link         |
| Weight     | Cost / Delay |

---

### Nguyên lý hoạt động

Thuật toán tìm đường đi có tổng cost nhỏ nhất từ source đến destination.

Pseudo-code:

```
dist[source] = 0

while còn node chưa xét:
    chọn node có dist nhỏ nhất
    cập nhật dist của các neighbor
```

---

### routing_dijkstra.pcap

File capture packet sau khi routing được thiết lập.

Có thể dùng **Wireshark** để kiểm tra:

* đường đi của packet
* TTL
* header IP

---

## 4. Pipeline của toàn bộ project

Luồng thực hiện của project:

```
Traffic generation
      ↓
Mininet network
      ↓
Queue processing
      ↓
Packet logging
      ↓
Data analysis
```

---

## 5. Công cụ sử dụng

Project sử dụng các công cụ sau:

| Tool             | Mục đích          |
| ---------------- | ----------------- |
| Python           | viết script       |
| Mininet          | giả lập mạng      |
| Jupyter Notebook | phân tích dữ liệu |
| Wireshark        | phân tích packet  |
| tcpdump          | capture packet    |

---

## 6. Mục tiêu học thuật

Project giúp nghiên cứu:

### Queueing Theory

* Poisson arrival
* network congestion
* queue delay
* throughput

### Routing

* routing table
* shortest path algorithm
* packet forwarding

---

