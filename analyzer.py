"""
Network Traffic Analyzer - Analysis Module
Day 2: Traffic Analysis and Pattern Detection
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
import json

class TrafficAnalyzer:
    def __init__(self, csv_file):
        """Initialize analyzer with captured traffic CSV"""
        self.csv_file = csv_file
        self.df = None
        self.analysis_results = {}
        
    def load_data(self):
        """Load captured traffic from CSV"""
        try:
            print(f"Loading traffic data from {self.csv_file}...")
            self.df = pd.read_csv(self.csv_file)
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            print(f"✓ Loaded {len(self.df)} packets\n")
            return True
        except FileNotFoundError:
            print(f"Error: File '{self.csv_file}' not found!")
            return False
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def basic_statistics(self):
        """Calculate basic traffic statistics"""
        print("=" * 60)
        print("BASIC TRAFFIC STATISTICS")
        print("=" * 60)
        
        stats = {
            'total_packets': len(self.df),
            'total_bytes': self.df['length'].sum(),
            'avg_packet_size': self.df['length'].mean(),
            'max_packet_size': self.df['length'].max(),
            'min_packet_size': self.df['length'].min(),
            'unique_src_ips': self.df['src_ip'].nunique(),
            'unique_dst_ips': self.df['dst_ip'].nunique(),
            'duration_seconds': (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds()
        }
        
        print(f"\nTotal Packets: {stats['total_packets']:,}")
        print(f"Total Bytes: {stats['total_bytes']:,} ({stats['total_bytes']/1024:.2f} KB)")
        print(f"Average Packet Size: {stats['avg_packet_size']:.2f} bytes")
        print(f"Packet Size Range: {stats['min_packet_size']} - {stats['max_packet_size']} bytes")
        print(f"\nUnique Source IPs: {stats['unique_src_ips']}")
        print(f"Unique Destination IPs: {stats['unique_dst_ips']}")
        print(f"Capture Duration: {stats['duration_seconds']:.2f} seconds")
        
        if stats['duration_seconds'] > 0:
            bandwidth = (stats['total_bytes'] * 8) / stats['duration_seconds'] / 1000  # Kbps
            print(f"Average Bandwidth: {bandwidth:.2f} Kbps")
        
        self.analysis_results['basic_stats'] = stats
        return stats
    
    def protocol_analysis(self):
        """Analyze protocol distribution"""
        print("\n" + "=" * 60)
        print("PROTOCOL ANALYSIS")
        print("=" * 60)
        
        protocol_counts = self.df['protocol'].value_counts()
        protocol_bytes = self.df.groupby('protocol')['length'].sum()
        
        print("\nPacket Distribution:")
        for protocol, count in protocol_counts.items():
            percentage = (count / len(self.df)) * 100
            bytes_sent = protocol_bytes[protocol]
            print(f"  {protocol}: {count} packets ({percentage:.1f}%) | {bytes_sent:,} bytes")
        
        self.analysis_results['protocols'] = protocol_counts.to_dict()
        return protocol_counts
    
    def top_talkers(self, top_n=10):
        """Identify most active IP addresses"""
        print("\n" + "=" * 60)
        print(f"TOP {top_n} MOST ACTIVE IPs")
        print("=" * 60)
        
        # Source IPs (outbound)
        src_activity = self.df.groupby('src_ip').agg({
            'length': 'sum',
            'src_ip': 'count'
        }).rename(columns={'src_ip': 'packet_count', 'length': 'total_bytes'})
        src_activity = src_activity.sort_values('packet_count', ascending=False).head(top_n)
        
        print("\nTop Senders (Outbound):")
        for idx, (ip, row) in enumerate(src_activity.iterrows(), 1):
            print(f"  {idx}. {ip}")
            print(f"     Packets: {row['packet_count']} | Bytes: {row['total_bytes']:,}")
        
        # Destination IPs (inbound)
        dst_activity = self.df.groupby('dst_ip').agg({
            'length': 'sum',
            'dst_ip': 'count'
        }).rename(columns={'dst_ip': 'packet_count', 'length': 'total_bytes'})
        dst_activity = dst_activity.sort_values('packet_count', ascending=False).head(top_n)
        
        print("\nTop Receivers (Inbound):")
        for idx, (ip, row) in enumerate(dst_activity.iterrows(), 1):
            print(f"  {idx}. {ip}")
            print(f"     Packets: {row['packet_count']} | Bytes: {row['total_bytes']:,}")
        
        self.analysis_results['top_talkers'] = {
            'senders': src_activity.to_dict('index'),
            'receivers': dst_activity.to_dict('index')
        }
        
        return src_activity, dst_activity
    
    def port_analysis(self):
        """Analyze port usage and detect common services"""
        print("\n" + "=" * 60)
        print("PORT ANALYSIS")
        print("=" * 60)
        
        # Common ports and their services
        common_ports = {
            20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP Alt', 27017: 'MongoDB'
        }
        
        # Filter out N/A ports
        dst_ports = self.df[self.df['dst_port'] != 'N/A']['dst_port'].value_counts().head(10)
        
        print("\nTop 10 Destination Ports:")
        for port, count in dst_ports.items():
            service = common_ports.get(int(port), 'Unknown')
            percentage = (count / len(self.df)) * 100
            print(f"  Port {port} ({service}): {count} packets ({percentage:.1f}%)")
        
        self.analysis_results['top_ports'] = dst_ports.to_dict()
        return dst_ports
    
    def detect_port_scan(self, threshold=10):
        """Detect potential port scanning activity"""
        print("\n" + "=" * 60)
        print("PORT SCAN DETECTION")
        print("=" * 60)
        
        # Group by source IP and count unique destination ports
        port_scan_candidates = self.df.groupby('src_ip')['dst_port'].nunique()
        suspicious = port_scan_candidates[port_scan_candidates >= threshold]
        
        if len(suspicious) > 0:
            print(f"\n⚠️  ALERT: Potential port scanning detected!")
            print(f"Threshold: {threshold} unique ports accessed\n")
            
            for ip, port_count in suspicious.items():
                print(f"  Source IP: {ip}")
                print(f"  Unique ports accessed: {port_count}")
                
                # Show which ports were accessed
                ports = self.df[self.df['src_ip'] == ip]['dst_port'].unique()
                ports_str = ', '.join(map(str, ports[:10]))
                if len(ports) > 10:
                    ports_str += f"... (+{len(ports)-10} more)"
                print(f"  Ports: {ports_str}\n")
            
            self.analysis_results['port_scan_detected'] = True
            self.analysis_results['suspicious_ips'] = suspicious.to_dict()
        else:
            print(f"\n✓ No port scanning activity detected (threshold: {threshold} ports)")
            self.analysis_results['port_scan_detected'] = False
        
        return suspicious
    
    def detect_unusual_traffic(self):
        """Detect unusual traffic patterns"""
        print("\n" + "=" * 60)
        print("UNUSUAL TRAFFIC DETECTION")
        print("=" * 60)
        
        alerts = []
        
        # 1. Unusually large packets (potential data exfiltration)
        mean_size = self.df['length'].mean()
        std_size = self.df['length'].std()
        large_packets = self.df[self.df['length'] > mean_size + (2 * std_size)]
        
        if len(large_packets) > 0:
            alert = f"⚠️  {len(large_packets)} unusually large packets detected (>2 std dev)"
            print(f"\n{alert}")
            for _, packet in large_packets.head(3).iterrows():
                print(f"  {packet['src_ip']} → {packet['dst_ip']} | {packet['length']} bytes")
            alerts.append(alert)
        
        # 2. High connection rate to single destination
        dst_connections = self.df.groupby('dst_ip').size()
        high_traffic_dsts = dst_connections[dst_connections > len(self.df) * 0.3]
        
        if len(high_traffic_dsts) > 0:
            alert = f"⚠️  High connection rate to {len(high_traffic_dsts)} destination(s)"
            print(f"\n{alert}")
            for ip, count in high_traffic_dsts.items():
                percentage = (count / len(self.df)) * 100
                print(f"  {ip}: {count} packets ({percentage:.1f}% of total traffic)")
            alerts.append(alert)
        
        # 3. Multiple protocols from same source (potential reconnaissance)
        src_protocols = self.df.groupby('src_ip')['protocol'].nunique()
        multi_protocol = src_protocols[src_protocols >= 3]
        
        if len(multi_protocol) > 0:
            alert = f"⚠️  {len(multi_protocol)} source(s) using multiple protocols"
            print(f"\n{alert}")
            for ip, protocol_count in multi_protocol.items():
                protocols = self.df[self.df['src_ip'] == ip]['protocol'].unique()
                print(f"  {ip}: {', '.join(protocols)}")
            alerts.append(alert)
        
        if not alerts:
            print("\n✓ No unusual traffic patterns detected")
        
        self.analysis_results['alerts'] = alerts
        return alerts
    
    def connection_pairs(self, top_n=10):
        """Analyze most common source-destination pairs"""
        print("\n" + "=" * 60)
        print(f"TOP {top_n} CONNECTION PAIRS")
        print("=" * 60)
        
        self.df['connection'] = self.df['src_ip'] + ' → ' + self.df['dst_ip']
        connections = self.df['connection'].value_counts().head(top_n)
        
        print("\nMost Frequent Connections:")
        for idx, (conn, count) in enumerate(connections.items(), 1):
            percentage = (count / len(self.df)) * 100
            print(f"  {idx}. {conn}")
            print(f"     {count} packets ({percentage:.1f}%)")
        
        return connections
    
    def time_series_analysis(self):
        """Analyze traffic over time"""
        print("\n" + "=" * 60)
        print("TIME SERIES ANALYSIS")
        print("=" * 60)
        
        self.df['time_bin'] = self.df['timestamp'].dt.floor('1s')  # 1-second bins
        
        packets_per_second = self.df.groupby('time_bin').size()
        bytes_per_second = self.df.groupby('time_bin')['length'].sum()
        
        print(f"\nPackets per second:")
        print(f"  Average: {packets_per_second.mean():.2f}")
        print(f"  Peak: {packets_per_second.max()}")
        print(f"  Minimum: {packets_per_second.min()}")
        
        print(f"\nBytes per second:")
        print(f"  Average: {bytes_per_second.mean():.2f}")
        print(f"  Peak: {bytes_per_second.max():,}")
        print(f"  Minimum: {bytes_per_second.min()}")
        
        return packets_per_second, bytes_per_second
    
    def export_analysis(self, output_file="data/processed/analysis_results.json"):
        """Export analysis results to JSON"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            print(f"\n✓ Analysis results exported to {output_file}")
        except Exception as e:
            print(f"Error exporting results: {e}")
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "=" * 70)
        print("COMPREHENSIVE TRAFFIC ANALYSIS REPORT")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        if self.df is None:
            print("No data loaded!")
            return
        
        # Run all analyses
        self.basic_statistics()
        self.protocol_analysis()
        self.top_talkers()
        self.port_analysis()
        self.connection_pairs()
        self.time_series_analysis()
        self.detect_port_scan()
        self.detect_unusual_traffic()
        
        print("\n" + "=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)


def main():
    """Main function to run traffic analysis"""
    
    print("\n" + "=" * 60)
    print("NETWORK TRAFFIC ANALYZER v1.0")
    print("Day 2: Traffic Analysis")
    print("=" * 60 + "\n")
    
    # Initialize analyzer
    analyzer = TrafficAnalyzer("data/captured/traffic_capture.csv")
    
    # Load data
    if not analyzer.load_data():
        return
    
    # Generate comprehensive report
    analyzer.generate_report()
    
    # Export results
    analyzer.export_analysis()
    
    print("\n✓ Analysis session complete!")
    print("Next: Day 3 - Machine Learning Anomaly Detection\n")


if __name__ == "__main__":
    main()