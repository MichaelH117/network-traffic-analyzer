"""
Network Traffic Analyzer - Packet Capture Module
Day 1: Basic packet capture and display
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv

class PacketCapture:
    def __init__(self):
        self.packets = []
        self.capture_count = 0
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            # Only process packets with IP layer
            if IP in packet:
                self.capture_count += 1
                
                # Extract basic packet info
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Determine protocol name
                if TCP in packet:
                    protocol_name = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol_name = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif ICMP in packet:
                    protocol_name = "ICMP"
                    src_port = "N/A"
                    dst_port = "N/A"
                else:
                    protocol_name = f"Protocol-{protocol}"
                    src_port = "N/A"
                    dst_port = "N/A"
                
                packet_length = len(packet)
                
                # Store packet info
                packet_info = {
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol_name,
                    'length': packet_length
                }
                
                self.packets.append(packet_info)
                
                # Print to console (first 20 packets for demo)
                if self.capture_count <= 20:
                    print(f"\n[Packet #{self.capture_count}]")
                    print(f"Time: {timestamp}")
                    print(f"Source: {src_ip}:{src_port}")
                    print(f"Destination: {dst_ip}:{dst_port}")
                    print(f"Protocol: {protocol_name}")
                    print(f"Length: {packet_length} bytes")
                    print("-" * 50)
                elif self.capture_count == 21:
                    print("\n[Continuing to capture packets silently...]")
                    print("Press Ctrl+C to stop capture\n")
                    
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_capture(self, count=100, interface=None):
        """Start capturing packets"""
        print("=" * 60)
        print("NETWORK TRAFFIC ANALYZER - PACKET CAPTURE")
        print("=" * 60)
        print(f"\nStarting packet capture...")
        print(f"Target: {count} packets")
        if interface:
            print(f"Interface: {interface}")
        print("\nCapturing packets (this may take a moment)...\n")
        
        try:
            # Capture packets
            # filter="ip" only captures IP packets (no ARP, etc.)
            sniff(prn=self.packet_callback, count=count, filter="ip", iface=interface)
            
            print(f"\n\n✓ Capture complete! Total packets captured: {self.capture_count}")
            
        except PermissionError:
            print("\n⚠️  ERROR: Permission denied!")
            print("On Windows: Run VSCode as Administrator")
            print("On Mac/Linux: Run with sudo or adjust permissions")
        except Exception as e:
            print(f"\n⚠️  ERROR: {e}")
    
    def save_to_csv(self, filename="captured_traffic.csv"):
        """Save captured packets to CSV file"""
        if not self.packets:
            print("No packets to save!")
            return
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 
                             'dst_port', 'protocol', 'length']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                writer.writerows(self.packets)
                
            print(f"\n✓ Saved {len(self.packets)} packets to '{filename}'")
            
        except Exception as e:
            print(f"Error saving to CSV: {e}")
    
    def display_summary(self):
        """Display basic statistics about captured traffic"""
        if not self.packets:
            print("No packets captured!")
            return
        
        print("\n" + "=" * 60)
        print("CAPTURE SUMMARY")
        print("=" * 60)
        
        # Count by protocol
        protocol_counts = {}
        for packet in self.packets:
            proto = packet['protocol']
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        print(f"\nTotal Packets: {len(self.packets)}")
        print("\nProtocol Distribution:")
        for proto, count in sorted(protocol_counts.items()):
            percentage = (count / len(self.packets)) * 100
            print(f"  {proto}: {count} packets ({percentage:.1f}%)")
        
        # Total bytes
        total_bytes = sum(p['length'] for p in self.packets)
        print(f"\nTotal Traffic: {total_bytes:,} bytes ({total_bytes/1024:.2f} KB)")
        
        # Most active IPs
        src_ips = {}
        for packet in self.packets:
            ip = packet['src_ip']
            src_ips[ip] = src_ips.get(ip, 0) + 1
        
        print("\nTop 5 Most Active Source IPs:")
        for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")


def main():
    """Main function to run the packet capture"""
    
    print("\n" + "=" * 60)
    print("NETWORK TRAFFIC ANALYZER v1.0")
    print("Day 1: Basic Packet Capture")
    print("=" * 60)
    
    # Create capture instance
    capture = PacketCapture()
    
    # Capture 50 packets (quick test)
    # For production, you'd capture more (1000+)
    capture.start_capture(count=50)
    
    # Display summary statistics
    capture.display_summary()
    
    # Save to CSV
    capture.save_to_csv("data/captured/traffic_capture.csv")
    
    print("\n" + "=" * 60)
    print("Capture session complete!")
    print("Next steps: Analyze the CSV file with pandas")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()