# Enhanced Scapy Traffic Analyzer Documentation

**Author:** KrustyKrab
**Date:** November, 2025
**Version:** 1.0

## 1. Overview

The **Enhanced Scapy Traffic Analyzer** is a Python-based network monitoring and security tool built upon the powerful **Scapy** library. It is designed to perform real-time packet capture, traffic analysis, and basic intrusion detection. The tool operates by sniffing packets on a selected network interface, analyzing them for protocol information, and applying security heuristics to detect suspicious activity.

## 2. Prerequisites

The analyzer requires the `scapy` library to function.

### Installation

```bash
# Install Scapy using pip3
sudo pip3 install scapy
```

### Execution

Due to the nature of packet sniffing, the script requires root or administrator privileges to access the network interface.

```bash
# Run the script with sudo
sudo python3 enhanced_packet_analyzer.py
```

The script will automatically attempt to find the most active network interface. The capture can be stopped at any time by pressing `Ctrl+C`.

## 3. Core Components

The analyzer is primarily composed of the `ScapyTrafficAnalyzer` class and two utility functions.

### 3.1. `ScapyTrafficAnalyzer` Class

This class manages the state of the analysis, processes individual packets, and handles reporting.

#### **Initialization (`__init__`)**

The constructor initializes several `defaultdict(int)` and `set` objects to store statistics, security states, and analysis results:

| Category | Attribute | Description |
| :--- | :--- | :--- |
| **General Stats** | `self.stats` | Stores counts for total packets, TCP, UDP, ICMP, ARP, and errors. |
| | `self.alerts` | A list to store all flagged security alerts. |
| | `self.start_time` | Timestamp of when the analyzer started. |
| **Security States** | `self.syn_count` | Tracks SYN packets per source IP for SYN Flood detection. |
| | `self.port_scan_tracker` | Tracks unique destination ports scanned by a source IP. |
| | `self.last_syn_reset` | Timestamp for resetting the SYN count window. |
| **DNS Analysis** | `self.dns_queries` | Stores the count of queries for each unique domain name. |
| | `self.suspicious_domains` | Stores domains flagged as potentially DGA-like to prevent duplicate alerts. |
| **HTTP Analysis** | `self.http_requests` | Stores the count of requests for each unique HTTP Host. |
| | `self.http_user_agents` | Stores the count of requests for each unique User-Agent string. |
| | `self.http_suspicious_requests` | Stores messages for requests flagged as potential web attacks. |

#### **Packet Processing (`analyze_packet`)**

This is the main callback function passed to Scapy's `sniff`. It performs the following steps:
1.  Increments the total packet count and updates the last packet time.
2.  Performs basic IP layer analysis (source/destination IP).
3.  Routes the packet to protocol-specific analysis methods:
    *   **TCP:** Calls `detect_port_scan`, `detect_syn_flood`, `detect_suspicious_ports`, and the new `analyze_http`.
    *   **UDP:** Calls `detect_suspicious_ports` and the new `analyze_dns`.
    *   **ICMP/ARP:** Increments respective counters.
4.  Triggers the `print_stats` method periodically (every 50 packets) for real-time monitoring.

### 3.2. Security Detection Methods

The analyzer implements several heuristics for detecting malicious or suspicious network activity.

| Method | Detection Logic | Severity |
| :--- | :--- | :--- |
| `detect_port_scan` | Flags an alert if a single source IP attempts to connect to **more than 15 unique destination ports**. | HIGH |
| `detect_syn_flood` | Flags an alert if a single source IP sends **more than 20 SYN packets** within a 10-second window. | HIGH |
| `detect_suspicious_ports` | Flags an alert if traffic is observed on a predefined list of ports associated with malware, backdoors, or unencrypted/bruteforce-prone services (e.g., 4444, 31337, 22, 23, 3389). | MEDIUM |

### 3.3. Enhanced Analysis Features

#### **DNS Analysis (`analyze_dns`)**

This method focuses on UDP packets containing the DNS layer.
*   **Query Logging:** It extracts the domain name from DNS queries (`qr == 0`) and tallies the count for each unique domain in `self.dns_queries`.
*   **DGA Detection:** It implements a simple heuristic to detect **Domain Generation Algorithm (DGA)** activity, which is a common technique used by malware to generate a large number of potential command-and-control (C2) domains. The current check flags domains where the first part of the domain is **longer than 15 characters** and has **high character entropy** (more than 10 unique characters).

#### **HTTP Analysis (`analyze_http`)**

This method inspects TCP packets on standard HTTP ports (80, 8080) for raw payload data.
*   **Request Logging:** It uses regular expressions to extract and tally the `Host` and `User-Agent` headers from HTTP requests.
*   **Web Attack Detection:** It performs a basic check for common web attack patterns within the request payload, specifically looking for signatures of **SQL Injection** (`select...from`, `union...select`, `--`, `drop`, `sleep(`) or **Cross-Site Scripting (XSS)**.

### 3.4. Reporting Methods

#### **Alert Flagging (`flag_alert`)**

This utility method standardizes the logging and display of security alerts. It records the timestamp, message, and severity, and prints the alert to the console with a corresponding emoji for visual clarity.

#### **Statistics and Summary (`print_stats`)**

This method generates a comprehensive, multi-section report, both periodically during the capture and as a final summary upon exit.

The report sections include:
1.  **General Statistics:** Total packets, packet rate, duration, total alerts, and protocol breakdown (TCP, UDP, ICMP, ARP).
2.  **Top DNS Queries:** A list of the top 5 most frequently queried domain names.
3.  **Top HTTP Hosts:** A list of the top 5 most frequently accessed HTTP hosts.
4.  **Recent Alerts:** A list of the last 5 security alerts flagged during the capture session.

### 3.5. Utility Functions

#### **Interface Discovery (`find_active_interface`)**

This function automatically scans all available network interfaces (excluding loopback) by attempting to sniff a few packets. It selects the interface that captures the most traffic, providing a robust way to start the analysis without manual configuration.

#### **Main Execution (`live_capture_scapy`)**

This function orchestrates the entire process:
1.  Calls `find_active_interface` to determine the target interface.
2.  Initializes the `ScapyTrafficAnalyzer`.
3.  Starts the Scapy `sniff` process, passing `analyzer.analyze_packet` as the callback function.
4.  Handles exceptions for `PermissionError` (requires `sudo`) and `KeyboardInterrupt` (stops the capture and prints the final report).

## 4. Future Enhancements

The current implementation provides a strong foundation. Potential future enhancements could include:

*   **TLS/SSL Analysis:** Implement techniques to extract SNI (Server Name Indication) from TLS handshake packets to identify encrypted destinations.
*   **Protocol Parsers:** Add specific parsers for other common protocols like FTP, SMTP, or SMB to extract metadata and detect protocol-specific anomalies.
*   **Alert Persistence:** Save alerts and statistics to a file (e.g., CSV, JSON) for long-term analysis and review.
*   **Traffic Visualization:** Integrate with a library like `matplotlib` to generate real-time or final-report visualizations of traffic volume and protocol distribution.
*   **Advanced DGA Detection:** Implement a more sophisticated DGA detection model based on character frequency analysis or machine learning.
*   **Bypassing NAT/PAT:** The current IP-based security checks (SYN Flood, Port Scan) may be less effective in environments with Network Address Translation (NAT) or Port Address Translation (PAT), as all internal traffic appears to originate from the gateway's IP. Future versions could track internal hosts by MAC address or use a more complex flow-based analysis.
