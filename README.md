
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
#second version:
sudo python3 network_security_enhanced_packet_analyzer.py
```

The script will automatically attempt to find the most active network interface. The capture can be stopped at any time by pressing `Ctrl+C`.

