#!/usr/bin/env python3
"""
Enhanced Network Security Monitor - Packet Analyzer
A comprehensive network traffic analyzer with improved intrusion detection capabilities
and raw packet data extraction for flagged packets.
"""

from scapy.all import *
from collections import defaultdict
import time
import sys
import re
import os
import binascii

# --- Configuration ---
# Directory to save raw packet data
RAW_DATA_DIR = "insecure_packet_data"
# Thresholds for security checks
PORT_SCAN_THRESHOLD = 15  # Unique ports
SYN_FLOOD_THRESHOLD = 20  # SYN packets in 10s window
# Time window for resetting SYN flood counter (in seconds)
SYN_FLOOD_WINDOW = 10


# --- ScapyTrafficAnalyzer Class ---
class ScapyTrafficAnalyzer:
    def __init__(self):
        # General Stats
        self.stats = defaultdict(int)
        self.alerts = []
        self.start_time = time.time()
        self.last_packet_time = time.time()

        # Security Detection States
        self.syn_count = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        self.last_syn_reset = time.time()
        self.alerted_ips = (
            set()
        )  # To prevent repeated alerts for the same IP in a short time

        # DNS Analysis
        self.dns_queries = defaultdict(int)  # Domain -> Count
        self.suspicious_domains = set()

        # HTTP Analysis
        self.http_requests = defaultdict(int)  # Host -> Count
        self.http_user_agents = defaultdict(int)  # User-Agent -> Count
        self.http_suspicious_requests = []

        # Ensure raw data directory exists
        if not os.path.exists(RAW_DATA_DIR):
            os.makedirs(RAW_DATA_DIR)
            print(f"Created directory for raw data: {RAW_DATA_DIR}")

    # --- Core Analysis Method ---
    def analyze_packet(self, packet):
        try:
            self.stats["total_packets"] += 1
            self.last_packet_time = time.time()

            # Check for IP layer
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst

                # TCP analysis
                if packet.haslayer(TCP):
                    self.stats["tcp_packets"] += 1
                    tcp = packet[TCP]
                    dst_port = tcp.dport

                    # Security checks
                    self.detect_port_scan(ip_src, dst_port)
                    self.detect_syn_flood(packet, ip_src)
                    self.detect_suspicious_ports(dst_port, ip_src, "TCP", packet)
                    self.analyze_http(packet)

                # UDP analysis
                elif packet.haslayer(UDP):
                    self.stats["udp_packets"] += 1
                    udp = packet[UDP]
                    dst_port = udp.dport

                    # Security checks
                    self.detect_suspicious_ports(dst_port, ip_src, "UDP", packet)
                    self.analyze_dns(packet)

                # ICMP analysis
                elif packet.haslayer(ICMP):
                    self.stats["icmp_packets"] += 1
                    self.detect_ping_flood(ip_src, packet)  # New: Ping flood detection

            # ARP packets
            elif packet.haslayer(ARP):
                self.stats["arp_packets"] += 1
                self.detect_arp_spoofing(packet)  # New: Basic ARP spoofing check

            # Print ongoing stats
            if self.stats["total_packets"] % 50 == 0:
                self.print_stats()

        except Exception as e:
            self.stats["error_packets"] += 1
            # print(f"Error processing packet: {e}", file=sys.stderr) # Debugging

    # --- New Feature: Raw Data Extraction ---
    def extract_raw_data(self, packet, alert_type):
        """Extracts and saves the raw packet data to a file."""
        try:
            raw_data = bytes(packet)

            # Create a unique filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"{RAW_DATA_DIR}/{timestamp}_{alert_type}_{self.stats['total_packets']}.raw"

            with open(filename, "wb") as f:
                f.write(raw_data)

            # Also save a human-readable hex dump for quick inspection
            hex_filename = f"{RAW_DATA_DIR}/{timestamp}_{alert_type}_{self.stats['total_packets']}.hex"
            with open(hex_filename, "w") as f:
                f.write(f"Alert Type: {alert_type}\n")
                f.write(f"Packet Number: {self.stats['total_packets']}\n")
                f.write(f"Source: {packet[IP].src if packet.haslayer(IP) else 'N/A'}\n")
                f.write(
                    f"Destination: {packet[IP].dst if packet.haslayer(IP) else 'N/A'}\n"
                )
                f.write("-" * 30 + "\n")
                f.write(binascii.hexlify(raw_data).decode("utf-8"))

            return filename
        except Exception as e:
            print(f"Error extracting raw data: {e}", file=sys.stderr)
            return None

    # --- DNS Analysis (Improved) ---
    def analyze_dns(self, packet):
        """Analyze DNS queries for suspicious activity."""
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_layer = packet[DNS]
            ip_src = packet[IP].src

            # Check if this is a DNS query (qr == 0)
            if dns_layer.qr == 0 and dns_layer.qd:
                try:
                    # Extract the domain name from the query
                    query_name = dns_layer.qd.qname.decode("utf-8").strip(".")

                    # Skip mDNS queries (local network service discovery)
                    if query_name.endswith(".local"):
                        return

                    self.dns_queries[query_name] += 1

                    # Simple check for long, random-looking domain names (DGA-like)
                    domain_parts = query_name.split(".")
                    if domain_parts:
                        first_part = domain_parts[0]
                        # Check if domain looks like DGA: long and high entropy
                        if len(first_part) > 15 and len(set(first_part)) > 10:
                            if query_name not in self.suspicious_domains:
                                alert_msg = (
                                    f"⚠️ DGA-LIKE DOMAIN: {query_name} from {ip_src}"
                                )
                                self.flag_alert(alert_msg, "MEDIUM", packet)
                                self.suspicious_domains.add(query_name)
                except (AttributeError, UnicodeDecodeError):
                    pass

    # --- HTTP Analysis (Improved) ---
    def analyze_http(self, packet):
        """Analyze HTTP requests for common web attacks or unusual activity."""
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            tcp = packet[TCP]
            dport = tcp.dport
            sport = tcp.sport

            # Check if traffic is on HTTP ports
            if dport in [80, 8080] or sport in [80, 8080]:
                try:
                    # Decode payload, handling potential decoding errors
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")

                    # Check for HTTP GET/POST request
                    if payload.startswith(
                        ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")
                    ):

                        # Extract Host header
                        host_match = re.search(
                            r"Host: (.*?)\r\n", payload, re.IGNORECASE
                        )
                        host = (
                            host_match.group(1).strip()
                            if host_match
                            else "Unknown Host"
                        )
                        self.http_requests[host] += 1

                        # Extract User-Agent
                        ua_match = re.search(
                            r"User-Agent: (.*?)\r\n", payload, re.IGNORECASE
                        )
                        if ua_match:
                            user_agent = ua_match.group(1).strip()
                            self.http_user_agents[user_agent] += 1

                        # Simple check for SQL Injection or XSS in URL/Payload
                        # Added more common attack patterns
                        attack_patterns = r"select.+from|union.+select|--|drop|sleep\(|alert\(|onload=|onmouseover=|script>"
                        if re.search(
                            attack_patterns,
                            payload,
                            re.IGNORECASE
                            | re.DOTALL,  # re.DOTALL to match across newlines
                        ):
                            alert_msg = f"🚨 WEB ATTACK: Possible SQLi/XSS detected in HTTP request to {host}"
                            self.flag_alert(alert_msg, "HIGH", packet)
                            self.http_suspicious_requests.append(alert_msg)

                except (UnicodeDecodeError, AttributeError):
                    # Ignore packets where payload decoding fails
                    pass

    # --- Security Detection Methods (Improved) ---
    def detect_port_scan(self, src_ip, dst_port):
        """Detect potential port scanning"""
        if src_ip in self.alerted_ips:
            return  # Skip if recently alerted

        self.port_scan_tracker[src_ip].add(dst_port)

        if len(self.port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
            alert_msg = f"🚨 PORT SCAN: {src_ip} scanned {len(self.port_scan_tracker[src_ip])} unique ports"
            # Flag alert with packet=None as this is a cumulative alert
            self.flag_alert(alert_msg, "HIGH", packet=None)
            self.alerted_ips.add(src_ip)
            # Do not reset tracker immediately, but add a timeout mechanism (not implemented here for simplicity)

    def detect_syn_flood(self, packet, src_ip):
        """Detect SYN flood attacks"""
        if src_ip in self.alerted_ips:
            return  # Skip if recently alerted

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags == "S":  # SYN packet
                self.syn_count[src_ip] += 1

                # Reset counter every SYN_FLOOD_WINDOW seconds
                if time.time() - self.last_syn_reset > SYN_FLOOD_WINDOW:
                    self.syn_count.clear()
                    self.last_syn_reset = time.time()

                # Alert if more than THRESHOLD SYN packets from same IP
                if self.syn_count[src_ip] > SYN_FLOOD_THRESHOLD:
                    alert_msg = f"🚨 SYN FLOOD: {src_ip} sent {self.syn_count[src_ip]} SYN packets"
                    self.flag_alert(alert_msg, "HIGH", packet)
                    self.alerted_ips.add(src_ip)

    def detect_suspicious_ports(self, dst_port, src_ip, protocol, packet):
        """Detect traffic on suspicious ports"""
        suspicious_ports = {
            4444: "Metasploit",
            31337: "Back Orifice",
            1337: "LEET/Various",
            9999: "Malware",
            666: "Doom/Malware",
            54320: "Back Orifice 2",
            12345: "NetBus",
            2323: "Telnet alternative",
            20: "FTP Data (often abused)",
            21: "FTP Control (often abused)",
            22: "SSH (bruteforce target)",
            23: "Telnet (unencrypted)",
            3389: "RDP (bruteforce target)",
            # Added more common suspicious ports
            25: "SMTP (open relay/spam)",
            110: "POP3 (unencrypted)",
            143: "IMAP (unencrypted)",
            445: "SMB (vulnerability target)",
            139: "NetBIOS (vulnerability target)",
        }

        if dst_port in suspicious_ports:
            alert_msg = f"🔍 SUSPICIOUS PORT: {src_ip} → port {dst_port} ({protocol}) - {suspicious_ports[dst_port]}"
            self.flag_alert(alert_msg, "MEDIUM", packet)

    def detect_ping_flood(self, src_ip, packet):
        """New: Detect basic ping flood (ICMP echo request rate)"""
        # Simple rate limiting check: track ICMP requests per IP
        # For simplicity, we'll just count and alert on a high number in a short time.
        # A more robust solution would use a sliding window.
        self.stats[f"icmp_req_{src_ip}"] += 1

        # Reset counter every 5 seconds
        if time.time() - self.start_time > 5:
            # Check if the count is excessive (e.g., > 50 requests in 5 seconds)
            if self.stats[f"icmp_req_{src_ip}"] > 50 and src_ip not in self.alerted_ips:
                alert_msg = f"⚠️ PING FLOOD: {src_ip} sent {self.stats[f'icmp_req_{src_ip}']} ICMP requests in 5s"
                self.flag_alert(alert_msg, "MEDIUM", packet)
                self.alerted_ips.add(src_ip)

            # Reset all ICMP counters (simple reset for all IPs)
            for key in list(self.stats.keys()):
                if key.startswith("icmp_req_"):
                    self.stats[key] = 0
            self.start_time = time.time()  # Reset the time reference for this check

    def detect_arp_spoofing(self, packet):
        """New: Basic check for gratuitous ARP replies (a common sign of spoofing)"""
        if packet.op == 2:  # ARP is-at (reply)
            # Check if the source IP in the ARP reply is different from the sender IP in the Ethernet frame
            # This is a very basic check and can have false positives.
            if packet.haslayer(Ether) and packet[Ether].src != packet[ARP].hwsrc:
                alert_msg = f"🚨 ARP SPOOFING SUSPECT: MAC mismatch in ARP reply. Sender MAC: {packet[ARP].hwsrc}, Ethernet MAC: {packet[Ether].src}"
                self.flag_alert(alert_msg, "HIGH", packet)

    # --- Reporting Methods (Modified to include raw data extraction) ---
    def flag_alert(self, message, severity, packet=None):
        """Record and display alerts, and extract raw data if a packet is provided."""
        raw_data_file = None
        if packet is not None:
            raw_data_file = self.extract_raw_data(packet, severity)

        alert = {
            "timestamp": time.strftime("%H:%M:%S"),
            "message": message,
            "severity": severity,
            "raw_data_file": raw_data_file,
        }
        self.alerts.append(alert)

        colors = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "🔍"}
        file_info = (
            f" [RAW: {os.path.basename(raw_data_file)}]" if raw_data_file else ""
        )
        print(
            f"{colors.get(severity, '📝')} [{severity}] {alert['timestamp']} - {message}{file_info}"
        )

    def print_stats(self):
        """Print current statistics and summary report"""
        current_time = time.time()
        elapsed = current_time - self.start_time

        print(f"\n{'='*70}")
        print(f"📊 TRAFFIC ANALYSIS REPORT - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}")

        # 1. General Statistics
        print("\n--- 1. General Statistics ---")
        if elapsed > 0:
            packets_per_sec = self.stats["total_packets"] / elapsed
            print(f"⏱️  Duration: {elapsed:.1f}s")
            print(
                f"📦 Total Packets: {self.stats['total_packets']} | Rate: {packets_per_sec:.1f} packets/s"
            )
            print(f"🚨 Total Alerts: {len(self.alerts)}")
            print(f"❌ Error Packets: {self.stats['error_packets']}")
            print(
                f"📨 TCP: {self.stats['tcp_packets']} | UDP: {self.stats['udp_packets']} | ICMP: {self.stats.get('icmp_packets', 0)} | ARP: {self.stats['arp_packets']}"
            )

        # 2. Top DNS Queries
        print("\n--- 2. Top DNS Queries ---")
        if self.dns_queries:
            top_dns = sorted(
                self.dns_queries.items(), key=lambda item: item[1], reverse=True
            )[:5]
            for domain, count in top_dns:
                print(f"  - {domain}: {count} queries")
        else:
            print("  No DNS queries observed.")

        # 3. Top HTTP Hosts
        print("\n--- 3. Top HTTP Hosts ---")
        if self.http_requests:
            top_http = sorted(
                self.http_requests.items(), key=lambda item: item[1], reverse=True
            )[:5]
            for host, count in top_http:
                print(f"  - {host}: {count} requests")
        else:
            print("  No HTTP requests observed.")

        # 4. Recent Alerts
        print("\n--- 4. Recent Alerts ---")
        if self.alerts:
            for alert in self.alerts[-5:]:
                file_info = (
                    f" [RAW: {os.path.basename(alert['raw_data_file'])}]"
                    if alert["raw_data_file"]
                    else ""
                )
                print(
                    f"  {alert['timestamp']} [{alert['severity']}] - {alert['message']}{file_info}"
                )
        else:
            print("  No security alerts flagged.")

        print(f"{'='*70}\n")


# --- Utility Functions ---
def find_active_interface():
    """Find the interface with the most traffic"""
    print("🔍 Scanning for active interfaces...")

    try:
        interfaces = get_if_list()
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return "lo"

    interface_traffic = {}

    # Prioritize interfaces that are not loopback and not 'any'
    valid_interfaces = [iface for iface in interfaces if iface not in ("lo", "any")]

    for iface in valid_interfaces:
        try:
            print(f"  Testing {iface}...", end=" ")
            # Capture a few packets to see if there's traffic
            packets = sniff(iface=iface, count=3, timeout=2, quiet=True)
            packet_count = len(packets)
            interface_traffic[iface] = packet_count
            print(f"found {packet_count} packets")
        except Exception as e:
            print(f"failed ({type(e).__name__})")
            interface_traffic[iface] = 0

    # Return interface with most traffic
    if interface_traffic:
        best_interface = max(interface_traffic, key=interface_traffic.get)
        if interface_traffic[best_interface] > 0:
            print(f"✅ Selected {best_interface} (most active)")
            return best_interface

    # Fallback to 'any' if no traffic found on specific interfaces
    if "any" in interfaces:
        print("⚠️  Using 'any' as fallback (captures all interfaces)")
        return "any"
    elif valid_interfaces:
        print(f"⚠️  Using {valid_interfaces[0]} as fallback")
        return valid_interfaces[0]

    print("⚠️  Using 'lo' as ultimate fallback")
    return "lo"


# --- Main Execution Function ---
def live_capture_scapy():
    """Start live packet capture using scapy"""

    # Find the best interface automatically
    target_interface = sys.argv[1] if len(sys.argv) > 1 else find_active_interface()

    print(f"\n🎯 Starting capture on: {target_interface}")
    print("   Raw packet data for flagged packets will be saved to: " + RAW_DATA_DIR)
    print("   Press Ctrl+C to stop\n")

    analyzer = ScapyTrafficAnalyzer()

    try:
        # Start capture
        # store=0 ensures packets are not stored in memory, saving resources
        sniff(iface=target_interface, prn=analyzer.analyze_packet, store=0)

    except PermissionError:
        print("\n❌ Permission denied! Need root access.")
        print("Run with: sudo python3 enhanced_packet_analyzer.py")

    except KeyboardInterrupt:
        print("\n🛑 Capture stopped")
        analyzer.print_stats()  # Final summary report

    except Exception as e:
        print(f"\n💥 Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    live_capture_scapy()
