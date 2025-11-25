# 🛡️ Packet Analyzer --- Security Detection Logic (Detailed Markdown Analysis)

This document explains the inner workings of three important detection
components inside the **Enhanced Network Security Monitor**:

1.  **SYN Flood Detection**
2.  **Suspicious Port Detection**
3.  **Unified Alert Logging System**

------------------------------------------------------------------------

# 🧩 1. `detect_syn_flood()` --- SYN Flood Detection

A **SYN flood attack** attempts to overwhelm a target by sending a very
large number of TCP SYN packets without completing the 3-way handshake.

## ✔ Purpose

Detect excessive SYN packets from a single IP within a short time
window.

------------------------------------------------------------------------

## 🔍 Code Logic

``` python
def detect_syn_flood(self, packet, src_ip):
    if packet.haslayer(TCP):
        tcp = packet[TCP]

        # Check if packet is a SYN
        if tcp.flags == "S":
            self.syn_count[src_ip] += 1

            # Reset every 10 seconds
            if time.time() - self.last_syn_reset > 10:
                self.syn_count.clear()
                self.last_syn_reset = time.time()

            # Trigger alert if >20 SYNs from same IP
            if self.syn_count[src_ip] > 20:
                alert_msg = f"SYN FLOOD: {src_ip} sent {self.syn_count[src_ip]} SYN packets"
                self.flag_alert(alert_msg, "HIGH")
```

------------------------------------------------------------------------

## 🧠 Step-by-Step Explanation

### 1. Detect SYN packets

SYN-only packets indicate handshake attempts.

### 2. Count SYNs per source IP

This monitors burst behavior.

### 3. Reset counter every 10 seconds

Implements a sliding time window.

### 4. Alert if threshold exceeded

More than **20 SYNs in 10 seconds** = suspicious.

------------------------------------------------------------------------

# 🔥 2. `detect_suspicious_ports()` --- Dangerous Port Detection

Detects traffic hitting ports known for malware, exploits, or
brute-force activity.

------------------------------------------------------------------------

## 🔍 Code Logic

``` python
def detect_suspicious_ports(self, dst_port, src_ip, protocol):
    suspicious_ports = {
        4444: "Metasploit",
        31337: "Back Orifice",
        1337: "LEET/Various",
        9999: "Malware",
        666: "Doom/Malware",
        54320: "Back Orifice 2",
        12345: "NetBus",
        2323: "Telnet alternative",
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
    }

    if dst_port in suspicious_ports:
        alert_msg = (
            f"SUSPICIOUS PORT: {src_ip} → port {dst_port} ({protocol}) - "
            f"{suspicious_ports[dst_port]}"
        )
        self.flag_alert(alert_msg, "MEDIUM")
```

------------------------------------------------------------------------

# 🚨 3. `flag_alert()` --- Unified Alert System

Handles formatting, storing, and printing standardized alerts.

------------------------------------------------------------------------

## 🔍 Code Logic

``` python
def flag_alert(self, message, severity):
    alert = {
        "timestamp": time.strftime("%H:%M:%S"),
        "message": message,
        "severity": severity,
    }
    self.alerts.append(alert)

    colors = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "🔍"}
    print(
        f"{colors.get(severity, '📝')} [{severity}] {alert['timestamp']} - {message}"
    )
```

------------------------------------------------------------------------

# 📌 Summary Table

  ----------------------------------------------------------------------------
  System             Purpose           Trigger             Severity
  ------------------ ----------------- ------------------- -------------------
  **SYN Flood        Detect excessive  \>20 SYNs / 10s     🚨 HIGH
  Detector**         SYN packets                           

  **Suspicious Ports Monitor           Malware/backdoor    ⚠️ MEDIUM
  Detector**         connections to    port list           
                     dangerous ports                       

  **flag_alert()**   Unified alert     Any detection event 🔍 ⚠️ 🚨
                     logging                               
  ----------------------------------------------------------------------------

------------------------------------------------------------------------
