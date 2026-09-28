# Cybersecurity Network Monitoring System (Mini Project)

A beginner-friendly, terminal-based **Cybersecurity Network Monitoring Mini Project** built in **Python 3** for **Ubuntu Linux**, **Kali Linux**, and cross-platform Linux/Windows environments. The application monitors host availability, calculates latency and packet loss using ICMP ping requests, performs non-intrusive TCP port status checks, and generates structured security audit reports in both plain text (`.txt`) and CSV formats.

---

## 1. Project Abstract

In modern IT infrastructure and cybersecurity operations, continuous network monitoring is essential for maintaining service availability, identifying unauthorized or unreachable endpoints, and diagnosing connectivity bottlenecks. The **Cybersecurity Network Monitoring System** is a lightweight, educational tool developed in Python 3. Designed specifically for Ubuntu Linux, Kali Linux, and educational Linux environments, the system evaluates the real-time operational status of target hosts using standard network protocols (ICMP and TCP). It resolves domain names to IPv4 addresses, measures round-trip latency, calculates packet loss percentages, verifies accessibility of key service ports (such as SSH, HTTP, and HTTPS), and automatically logs security findings into structured text and CSV reports.

---

## 2. Project Objectives

- **Cross-Platform Linux Compatibility**: Runs seamlessly out of the box on **Ubuntu Linux**, **Kali Linux**, **Debian**, and Windows.
- **Host Reachability & Status Check**: Determine whether a target server or IP address is `UP` or `DOWN`.
- **DNS Resolution**: Convert domain names (e.g., `google.com`) to valid IPv4 addresses (e.g., `8.8.8.8`).
- **Performance & Latency Analysis**: Measure network response time (RTT in milliseconds) and packet loss percentage over multiple ping attempts.
- **Port Availability Verification**: Inspect basic TCP connectivity for common service ports (Port 22 SSH, Port 80 HTTP, Port 443 HTTPS) without aggressive or illegal port scanning.
- **Automated Security Reporting**: Record timestamped monitoring logs in `reports/` directory formatted in plain text (`.txt`) and tabular CSV (`.csv`) for auditing.
- **Pure Standard Library Implementation**: Utilize native Python 3 modules (`socket`, `subprocess`, `time`, `datetime`, `csv`) without requiring third-party dependencies.

---

## 3. Project Structure

```
cyber-network-monitor/
│
├── main.py               # Main CLI interface and interactive menu controller
├── network_monitor.py    # DNS resolution, ICMP ping execution, latency & packet loss logic
├── port_scanner.py       # TCP socket port checking and service identification
├── report_generator.py   # Text & CSV report generation with automated security observation
├── requirements.txt      # List of standard library requirements and Python environment specs
├── README.md             # Comprehensive project documentation & user guide
└── reports/              # Output folder for generated reports
    └── .gitkeep          # Git placeholder to retain reports directory
```

---

## 4. Module Explanations

### `main.py`
Serves as the entry point and terminal user dashboard. It manages the CLI user menu, coordinates user inputs, invokes host resolution and scanning modules, displays real-time formatted monitoring results, and handles user exceptions gracefully.

### `network_monitor.py`
Implements the `NetworkMonitor` class. Uses `socket.gethostbyname()` for IPv4 DNS resolution. Runs system `ping` requests via `subprocess.run()`, parses the console output using regular expressions (`re`), and computes response times (ms) and packet loss percentage. Handles OS differences between Ubuntu/Linux and Windows automatically.

### `port_scanner.py`
Implements the `PortScanner` class. Uses standard `socket.socket(socket.AF_INET, socket.SOCK_STREAM)` to perform lightweight TCP handshake checks (`connect_ex`) against target ports (e.g., 22, 80, 443). Determines whether a port is `OPEN` or `CLOSED/FILTERED` within a set timeout limit.

### `report_generator.py`
Implements the `ReportGenerator` class. Takes structured dictionary data from monitoring scans, synthesizes an automated security observation summary, and generates formatted text files (`reports/network_report_YYYY-MM-DD_HHMMSS.txt`) as well as appending rows to `reports/network_monitor.csv`.

---

## 5. Ubuntu Linux & Kali Linux Setup Commands

Run the following commands in your **Ubuntu** or **Kali Linux** terminal to set up and run the application:

### On Ubuntu Linux:
```bash
# 1. Update package repository & ensure Python 3 and ping utilities are installed
sudo apt update
sudo apt install -y python3 iputils-ping

# 2. Create project directory or enter cloned folder
mkdir -p cyber-network-monitor
cd cyber-network-monitor

# 3. Launch the application
python3 main.py
```

### On Kali Linux:
```bash
# 1. Verify Python 3 installation
python3 --version

# 2. Navigate to project folder
mkdir -p cyber-network-monitor
cd cyber-network-monitor

# 3. Launch the application
python3 main.py
```

*Note: No third-party pip packages are required as the application relies exclusively on standard Python 3 libraries.*

---

## 6. How to Run the Application

1. Open your terminal in Ubuntu or Kali Linux.
2. Execute `python3 main.py`.
3. Input your desired Target Host or IP (e.g., `google.com` or `8.8.8.8`).
4. Select an option from the interactive menu:
   - `[1] Check Host`: Quick reachability and ping statistics.
   - `[2] Check Port`: Check TCP port availability (Custom ports or default 22, 80, 443).
   - `[3] Full Network Scan`: Run host availability, latency check, packet loss, and port scans.
   - `[4] Generate Security Report`: Save detailed text and CSV reports to `reports/`.
   - `[5] Change Target Host/IP`: Switch target host without restarting.
   - `[6] Extract IP Address from Domain`: Extract and output all IPv4/IPv6 addresses of a domain line by line (`\n`).
   - `[7] All-in-One Complete Audit`: Perform domain IP extraction, ping latency check, TCP port scanning, and generate reports in one single automated action.
   - `[8] Exit`: Close the application.

---

## 7. Sample Terminal Output

```text
====================================================
            CYBERSECURITY NETWORK MONITOR           
====================================================

[*] Resolving target '8.8.8.8'...
[+] Successfully resolved '8.8.8.8' to 8.8.8.8

----------------------------------------------------
 Current Target Host/IP: 8.8.8.8
----------------------------------------------------
[1] Check Host (Ping & Latency)
[2] Check Port Availability
[3] Full Network Scan
[4] Generate Security Report (TXT & CSV)
[5] Change Target Host/IP
[6] Exit
----------------------------------------------------
Select option: 3

[*] Running Full Network Scan for 8.8.8.8 (8.8.8.8)...
[*] 1/2 Checking host reachability and latency...
[*] 2/2 Checking common ports ([22, 80, 443])...

---
## NETWORK MONITORING RESULT
----------------------------------------------------
Host            : 8.8.8.8
IP Address      : 8.8.8.8
Host Status     : UP
Response Time   : 24.52 ms
Packet Loss     : 0%
Port 22         : CLOSED/FILTERED
Port 80         : OPEN
Port 443        : OPEN
Timestamp       : 26-09-2026 19:30:25
----------------------------------------------------
```

---

## 8. Example Generated Reports

### A. Plain Text Report (`reports/network_report_2026-09-26_193025.txt`)

```text
====================================================
         CYBERSECURITY NETWORK MONITOR REPORT       
====================================================
Target Host     : 8.8.8.8
IP Address      : 8.8.8.8
Host Status     : UP
Response Time   : 24.52 ms
Packet Loss     : 0%
----------------------------------------------------
PORT STATUS DETAILS:
  - Port 22    (SSH (Secure Shell)): CLOSED/FILTERED
  - Port 80    (HTTP (Web Server)): OPEN
  - Port 443   (HTTPS (Secure Web Server)): OPEN
----------------------------------------------------
Timestamp       : 26-09-2026 19:30:25
----------------------------------------------------
SECURITY OBSERVATION:
Host is UP with latency of 24.52 ms and 0% packet loss. Reachable open ports/services: Port 80 (HTTP (Web Server)), Port 443 (HTTPS (Secure Web Server)). Network stability appears optimal with 0% packet loss.
====================================================
```

### B. CSV Report Log (`reports/network_monitor.csv`)

```csv
Timestamp,Target Host,IP Address,Host Status,Response Time (ms),Packet Loss (%),Open Ports,Observation
26-09-2026 19:30:25,8.8.8.8,8.8.8.8,UP,24.52,0.0,"80,443","Host is UP with latency of 24.52 ms and 0% packet loss. Reachable open ports/services: Port 80, Port 443."
```

---

## 9. Future Enhancements

- **Graphical User Interface (GUI)**: Develop a PySimpleGUI or Tkinter dashboard for visual network graphs and latency trends over time.
- **Multithreaded Port Scanning**: Implement Python `concurrent.futures` or `threading` for faster scanning across larger custom port lists.
- **Email / Telegram Alerts**: Send instant notifications to system administrators when host status changes from `UP` to `DOWN`.
- **Subnet Monitoring**: Extend monitoring scope from single host to local network CIDR blocks (e.g., `192.168.1.0/24`).
- **SSL/TLS Certificate Checker**: Inspect target HTTPS certificates for expiry dates and cipher strength.

---

## 10. Safety & Educational Disclaimer

This tool was created strictly for educational purposes and authorized network administration testing. It executes only basic ICMP ping requests and standard TCP connection attempts against single user-specified targets. It does not contain any exploit payloads, stealth scanning algorithms, brute-force engines, or aggressive vulnerability probing mechanisms.
