#!/usr/bin/env python3
"""
Enhanced Network Security Monitor - Packet Analyzer
A comprehensive network traffic analyzer with intrusion detection capabilities.
"""

from scapy.all import *
from collections import defaultdict
import time
import sys
import re


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

        # New Feature: DNS Analysis
        self.dns_queries = defaultdict(int)  # Domain -> Count
        self.suspicious_domains = set()

        # New Feature: HTTP Analysis
        self.http_requests = defaultdict(int)  # Host -> Count
        self.http_user_agents = defaultdict(int)  # User-Agent -> Count
        self.http_suspicious_requests = []

    # --- Core Analysis Method ---
    def analyze_packet(self, packet):
        try:
            self.stats["total_packets"] += 1
            self.last_packet_time = time.time()

            # Show first few packets to confirm capture
            if self.stats["total_packets"] <= 3:
                print(f"📦 Packet {self.stats['total_packets']}: ", end="")

            # Check for IP layer
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst

                if self.stats["total_packets"] <= 3:
                    print(f"{ip_src} -> {ip_dst}", end="")

                # TCP analysis
                if packet.haslayer(TCP):
                    self.stats["tcp_packets"] += 1
                    tcp = packet[TCP]
                    dst_port = tcp.dport

                    if self.stats["total_packets"] <= 3:
                        print(f" :{dst_port} [TCP]")

                    self.detect_port_scan(ip_src, dst_port)
                    self.detect_syn_flood(packet, ip_src)
                    self.detect_suspicious_ports(dst_port, ip_src, "TCP")
                    self.analyze_http(packet)  # New: HTTP analysis

                # UDP analysis
                elif packet.haslayer(UDP):
                    self.stats["udp_packets"] += 1
                    udp = packet[UDP]
                    dst_port = udp.dport

                    if self.stats["total_packets"] <= 3:
                        print(f" :{dst_port} [UDP]")

                    self.detect_suspicious_ports(dst_port, ip_src, "UDP")
                    self.analyze_dns(packet)  # New: DNS analysis

                # ICMP analysis
                elif packet.haslayer(ICMP):
                    self.stats["icmp_packets"] += 1
                    if self.stats["total_packets"] <= 3:
                        print(" [ICMP]")

                else:
                    if self.stats["total_packets"] <= 3:
                        print(" [Other IP]")

            # ARP packets
            elif packet.haslayer(ARP):
                self.stats["arp_packets"] += 1
                if self.stats["total_packets"] <= 3:
                    print(f"ARP: {packet[ARP].psrc} -> {packet[ARP].pdst}")

            else:
                if self.stats["total_packets"] <= 3:
                    print(" [Other]")

            # Print stats after first few packets
            if self.stats["total_packets"] == 5:
                print(
                    "\n✅ Capture confirmed! Now monitoring for threats and analyzing traffic...\n"
                )

            # Print ongoing stats
            if self.stats["total_packets"] % 50 == 0:
                self.print_stats()

        except Exception as e:
            self.stats["error_packets"] += 1
            # Uncomment for debugging:
            # print(f"Error processing packet: {e}", file=sys.stderr)

    # --- New Feature: DNS Analysis ---
    def analyze_dns(self, packet):
        """Analyze DNS queries for suspicious activity."""
        try:
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]

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
                                    try:
                                        src_ip = (
                                            packet[IP].src
                                            if packet.haslayer(IP)
                                            else "Unknown"
                                        )
                                        alert_msg = f"⚠️ DGA-LIKE DOMAIN: {query_name} from {src_ip}"
                                        self.flag_alert(alert_msg, "MEDIUM")
                                        self.suspicious_domains.add(query_name)
                                    except:
                                        pass
                    except (AttributeError, UnicodeDecodeError):
                        pass
        except Exception as e:
            # Silently ignore DNS parsing errors
            pass

    # --- New Feature: HTTP Analysis ---
    def analyze_http(self, packet):
        """Analyze HTTP requests for common web attacks or unusual activity."""
        try:
            # Check for HTTP on standard ports (80, 8080) and raw data
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                tcp = packet[TCP]
                dport = tcp.dport
                sport = tcp.sport

                # Check if traffic is on HTTP ports
                if dport in [80, 8080] or sport in [80, 8080]:
                    try:
                        payload = packet[Raw].load.decode("utf-8", errors="ignore")

                        # Check for HTTP GET/POST request
                        if payload.startswith(
                            ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")
                        ):

                            # Extract Host header
                            host_match = re.search(
                                r"Host: (.*?)\r\n", payload, re.IGNORECASE
                            )
                            if host_match:
                                host = host_match.group(1).strip()
                                self.http_requests[host] += 1

                            # Extract User-Agent
                            ua_match = re.search(
                                r"User-Agent: (.*?)\r\n", payload, re.IGNORECASE
                            )
                            if ua_match:
                                user_agent = ua_match.group(1).strip()
                                self.http_user_agents[user_agent] += 1

                            # Simple check for SQL Injection or XSS in URL/Payload
                            if re.search(
                                r"select.+from|union.+select|--|drop|sleep\(",
                                payload,
                                re.IGNORECASE,
                            ):
                                host_str = (
                                    host_match.group(1).strip()
                                    if host_match
                                    else "Unknown Host"
                                )
                                alert_msg = f"🚨 WEB ATTACK: Possible SQLi/XSS detected in HTTP request to {host_str}"
                                self.flag_alert(alert_msg, "HIGH")
                                self.http_suspicious_requests.append(alert_msg)

                    except (UnicodeDecodeError, AttributeError):
                        # Ignore packets where payload decoding fails
                        pass
        except Exception as e:
            # Silently ignore HTTP parsing errors
            pass

    # --- Security Detection Methods ---
    def detect_port_scan(self, src_ip, dst_port):
        """Detect potential port scanning"""
        try:
            self.port_scan_tracker[src_ip].add(dst_port)

            if len(self.port_scan_tracker[src_ip]) > 15:
                alert_msg = f"🚨 PORT SCAN: {src_ip} scanned {len(self.port_scan_tracker[src_ip])} unique ports"
                self.flag_alert(alert_msg, "HIGH")
                # Reset after alert to avoid repeated alerts
                self.port_scan_tracker[src_ip] = set()
        except Exception as e:
            pass

    def detect_syn_flood(self, packet, src_ip):
        """Detect SYN flood attacks"""
        try:
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.flags == "S":  # SYN packet
                    self.syn_count[src_ip] += 1

                    # Reset counter every 10 seconds
                    if time.time() - self.last_syn_reset > 10:
                        self.syn_count.clear()
                        self.last_syn_reset = time.time()

                    # Alert if more than 20 SYN packets from same IP
                    if self.syn_count[src_ip] > 20:
                        alert_msg = f"🚨 SYN FLOOD: {src_ip} sent {self.syn_count[src_ip]} SYN packets"
                        self.flag_alert(alert_msg, "HIGH")
        except Exception as e:
            pass

    def detect_suspicious_ports(self, dst_port, src_ip, protocol):
        """Detect traffic on suspicious ports"""
        try:
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
            }

            if dst_port in suspicious_ports:
                alert_msg = f"🔍 SUSPICIOUS PORT: {src_ip} → port {dst_port} ({protocol}) - {suspicious_ports[dst_port]}"
                self.flag_alert(alert_msg, "MEDIUM")
        except Exception as e:
            pass

    # --- Reporting Methods ---
    def flag_alert(self, message, severity):
        """Record and display alerts"""
        try:
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
        except Exception as e:
            pass

    def print_stats(self):
        """Print current statistics and summary report"""
        try:
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
                    print(
                        f"  {alert['timestamp']} [{alert['severity']}] - {alert['message']}"
                    )
            else:
                print("  No security alerts flagged.")

            print(f"{'='*70}\n")
        except Exception as e:
            print(f"Error printing stats: {e}", file=sys.stderr)


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
    target_interface = find_active_interface()

    print(f"\n🎯 Starting capture on: {target_interface}")
    print("   Press Ctrl+C to stop\n")

    analyzer = ScapyTrafficAnalyzer()

    try:
        # Start capture
        sniff(iface=target_interface, prn=analyzer.analyze_packet, store=0)

    except PermissionError:
        print("\n❌ Permission denied! Need root access.")
        print("Run with: sudo python3 enhanced_packet_analyzer_fixed.py")

    except KeyboardInterrupt:
        print("\n🛑 Capture stopped")
        analyzer.print_stats()  # Final summary report

    except Exception as e:
        print(f"\n💥 Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    live_capture_scapy()
