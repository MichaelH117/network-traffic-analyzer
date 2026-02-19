"""
Network Traffic Analyzer - Visualization Module
Week 3: Data Visualization and HTML Report Generation
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import json
import os

# Set style for professional-looking plots
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)
plt.rcParams['font.size'] = 10

class TrafficVisualizer:
    def __init__(self, csv_file):
        """Initialize visualizer with captured traffic CSV"""
        self.csv_file = csv_file
        self.df = None
        self.output_dir = "reports"
        self.graphs_dir = os.path.join(self.output_dir, "graphs")
        
        # Create output directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.graphs_dir, exist_ok=True)
        
    def load_data(self):
        """Load captured traffic from CSV"""
        try:
            print(f"Loading traffic data from {self.csv_file}...")
            self.df = pd.read_csv(self.csv_file)
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            
            # Try to load ML results if available
            try:
                with open("data/processed/ml_analysis.json", 'r') as f:
                    self.ml_results = json.load(f)
            except:
                self.ml_results = None
            
            print(f"✓ Loaded {len(self.df)} packets\n")
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def plot_protocol_distribution(self):
        """Generate protocol distribution pie chart"""
        print("Creating protocol distribution chart...")
        
        plt.figure(figsize=(10, 6))
        
        protocol_counts = self.df['protocol'].value_counts()
        colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
        
        plt.pie(protocol_counts.values, 
                labels=protocol_counts.index,
                autopct='%1.1f%%',
                startangle=90,
                colors=colors[:len(protocol_counts)])
        
        plt.title('Network Traffic Protocol Distribution', fontsize=14, fontweight='bold')
        
        filepath = os.path.join(self.graphs_dir, 'protocol_distribution.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {filepath}")
        return filepath
    
    def plot_traffic_over_time(self):
        """Generate traffic volume over time"""
        print("Creating traffic over time chart...")
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Packets per second
        self.df['time_bin'] = self.df['timestamp'].dt.floor('1s')
        packets_per_sec = self.df.groupby('time_bin').size()
        
        ax1.plot(packets_per_sec.index, packets_per_sec.values, 
                marker='o', linewidth=2, markersize=6, color='#3498db')
        ax1.set_title('Packets Per Second', fontsize=12, fontweight='bold')
        ax1.set_ylabel('Packet Count')
        ax1.grid(True, alpha=0.3)
        
        # Bytes per second
        bytes_per_sec = self.df.groupby('time_bin')['length'].sum()
        
        ax2.plot(bytes_per_sec.index, bytes_per_sec.values / 1024, 
                marker='s', linewidth=2, markersize=6, color='#e74c3c')
        ax2.set_title('Traffic Volume Per Second', fontsize=12, fontweight='bold')
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Kilobytes (KB)')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        filepath = os.path.join(self.graphs_dir, 'traffic_over_time.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {filepath}")
        return filepath
    
    def plot_top_ips(self):
        """Generate top IPs bar chart"""
        print("Creating top IPs chart...")
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Top source IPs
        top_src = self.df['src_ip'].value_counts().head(5)
        ax1.barh(range(len(top_src)), top_src.values, color='#3498db')
        ax1.set_yticks(range(len(top_src)))
        ax1.set_yticklabels(top_src.index)
        ax1.set_xlabel('Packet Count')
        ax1.set_title('Top 5 Source IPs', fontsize=12, fontweight='bold')
        ax1.invert_yaxis()
        
        # Top destination IPs
        top_dst = self.df['dst_ip'].value_counts().head(5)
        ax2.barh(range(len(top_dst)), top_dst.values, color='#e74c3c')
        ax2.set_yticks(range(len(top_dst)))
        ax2.set_yticklabels(top_dst.index)
        ax2.set_xlabel('Packet Count')
        ax2.set_title('Top 5 Destination IPs', fontsize=12, fontweight='bold')
        ax2.invert_yaxis()
        
        plt.tight_layout()
        
        filepath = os.path.join(self.graphs_dir, 'top_ips.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {filepath}")
        return filepath
    
    def plot_port_analysis(self):
        """Generate port usage analysis"""
        print("Creating port analysis chart...")
        
        # Filter out N/A ports
        ports_df = self.df[self.df['dst_port'] != 'N/A'].copy()
        ports_df['dst_port'] = ports_df['dst_port'].astype(int)
        
        plt.figure(figsize=(12, 6))
        
        top_ports = ports_df['dst_port'].value_counts().head(10)
        
        # Common port names
        port_names = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        
        labels = [f"{port}\n({port_names.get(port, 'Unknown')})" for port in top_ports.index]
        
        bars = plt.bar(range(len(top_ports)), top_ports.values, color='#2ecc71')
        plt.xticks(range(len(top_ports)), labels, rotation=45, ha='right')
        plt.xlabel('Port (Service)')
        plt.ylabel('Packet Count')
        plt.title('Top 10 Destination Ports', fontsize=14, fontweight='bold')
        plt.grid(axis='y', alpha=0.3)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        
        filepath = os.path.join(self.graphs_dir, 'port_analysis.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {filepath}")
        return filepath
    
    def plot_packet_size_distribution(self):
        """Generate packet size distribution histogram"""
        print("Creating packet size distribution...")
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Histogram
        ax1.hist(self.df['length'], bins=20, color='#9b59b6', edgecolor='black', alpha=0.7)
        ax1.set_xlabel('Packet Size (bytes)')
        ax1.set_ylabel('Frequency')
        ax1.set_title('Packet Size Distribution', fontsize=12, fontweight='bold')
        ax1.grid(axis='y', alpha=0.3)
        
        # Box plot
        ax2.boxplot(self.df['length'], vert=True)
        ax2.set_ylabel('Packet Size (bytes)')
        ax2.set_title('Packet Size Statistics', fontsize=12, fontweight='bold')
        ax2.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        
        filepath = os.path.join(self.graphs_dir, 'packet_size_distribution.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {filepath}")
        return filepath
    
    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        print("\nGenerating HTML report...")
        
        # Calculate statistics
        stats = {
            'total_packets': len(self.df),
            'total_bytes': self.df['length'].sum(),
            'avg_packet_size': self.df['length'].mean(),
            'unique_src_ips': self.df['src_ip'].nunique(),
            'unique_dst_ips': self.df['dst_ip'].nunique(),
            'duration': (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds(),
            'protocols': self.df['protocol'].value_counts().to_dict()
        }
        
        # ML results if available
        ml_status = "Not Available"
        ml_section = ""
        if self.ml_results:
            anomaly_rate = self.ml_results['anomaly_rate']
            if anomaly_rate == 0:
                ml_status = '<span style="color: green;">✓ NORMAL</span>'
            elif anomaly_rate < 10:
                ml_status = '<span style="color: orange;">⚠️ LOW RISK</span>'
            elif anomaly_rate < 25:
                ml_status = '<span style="color: orange;">⚠️ MEDIUM RISK</span>'
            else:
                ml_status = '<span style="color: red;">🚨 HIGH RISK</span>'
            
            ml_section = f"""
            <div class="section">
                <h2>🤖 Machine Learning Analysis</h2>
                <div class="stat-grid">
                    <div class="stat-box">
                        <h3>{self.ml_results['total_packets']}</h3>
                        <p>Packets Analyzed</p>
                    </div>
                    <div class="stat-box">
                        <h3>{self.ml_results['anomalies_detected']}</h3>
                        <p>Anomalies Detected</p>
                    </div>
                    <div class="stat-box">
                        <h3>{self.ml_results['anomaly_rate']:.1f}%</h3>
                        <p>Anomaly Rate</p>
                    </div>
                    <div class="stat-box">
                        <h3>{ml_status}</h3>
                        <p>Security Status</p>
                    </div>
                </div>
            </div>
            """
        
        # HTML template
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 50px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .stat-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .stat-box h3 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .stat-box p {{
            font-size: 1em;
            opacity: 0.9;
        }}
        
        .graph {{
            margin: 30px 0;
            text-align: center;
        }}
        
        .graph img {{
            max-width: 100%;
            height: auto;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .protocol-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0;
        }}
        
        .protocol-item {{
            background: #f8f9fa;
            padding: 15px 25px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .protocol-item strong {{
            color: #667eea;
            font-size: 1.2em;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #666;
        }}
        
        .footer p {{
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Traffic Analysis Report</h1>
            <p>Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Traffic Overview</h2>
                <div class="stat-grid">
                    <div class="stat-box">
                        <h3>{stats['total_packets']:,}</h3>
                        <p>Total Packets</p>
                    </div>
                    <div class="stat-box">
                        <h3>{stats['total_bytes']/1024:.1f} KB</h3>
                        <p>Total Traffic</p>
                    </div>
                    <div class="stat-box">
                        <h3>{stats['avg_packet_size']:.0f}</h3>
                        <p>Avg Packet Size (bytes)</p>
                    </div>
                    <div class="stat-box">
                        <h3>{stats['duration']:.1f}s</h3>
                        <p>Capture Duration</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🌐 Network Statistics</h2>
                <div class="stat-grid">
                    <div class="stat-box">
                        <h3>{stats['unique_src_ips']}</h3>
                        <p>Unique Source IPs</p>
                    </div>
                    <div class="stat-box">
                        <h3>{stats['unique_dst_ips']}</h3>
                        <p>Unique Destination IPs</p>
                    </div>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #667eea;">Protocol Distribution:</h3>
                <div class="protocol-list">
                    {''.join([f'<div class="protocol-item"><strong>{proto}:</strong> {count} packets ({count/stats["total_packets"]*100:.1f}%)</div>' for proto, count in stats['protocols'].items()])}
                </div>
            </div>
            
            {ml_section}
            
            <div class="section">
                <h2>📈 Visual Analysis</h2>
                
                <div class="graph">
                    <h3>Protocol Distribution</h3>
                    <img src="graphs/protocol_distribution.png" alt="Protocol Distribution">
                </div>
                
                <div class="graph">
                    <h3>Traffic Over Time</h3>
                    <img src="graphs/traffic_over_time.png" alt="Traffic Over Time">
                </div>
                
                <div class="graph">
                    <h3>Top IP Addresses</h3>
                    <img src="graphs/top_ips.png" alt="Top IPs">
                </div>
                
                <div class="graph">
                    <h3>Port Analysis</h3>
                    <img src="graphs/port_analysis.png" alt="Port Analysis">
                </div>
                
                <div class="graph">
                    <h3>Packet Size Distribution</h3>
                    <img src="graphs/packet_size_distribution.png" alt="Packet Size Distribution">
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Network Traffic Analyzer v1.0</strong></p>
            <p>By Michael Hanson - Computer Science @ NJIT</p>
            <p>Powered by Python, Scapy, Pandas, scikit-learn & Matplotlib</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Save HTML report
        report_path = os.path.join(self.output_dir, 'traffic_report.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✓ HTML report saved to {report_path}")
        return report_path
    
    def generate_all_visuals(self):
        """Generate all visualizations and report"""
        print("=" * 60)
        print("GENERATING VISUALIZATIONS & REPORT")
        print("=" * 60 + "\n")
        
        # Generate all graphs
        self.plot_protocol_distribution()
        self.plot_traffic_over_time()
        self.plot_top_ips()
        self.plot_port_analysis()
        self.plot_packet_size_distribution()
        
        # Generate HTML report
        report_path = self.generate_html_report()
        
        print("\n" + "=" * 60)
        print("✓ VISUALIZATION COMPLETE!")
        print("=" * 60)
        print(f"\nOpen your report: {report_path}")
        print(f"All graphs saved in: {self.graphs_dir}")
        
        return report_path


def main():
    """Main function to generate visualizations"""
    
    print("\n" + "=" * 60)
    print("NETWORK TRAFFIC ANALYZER v1.0")
    print("Week 3: Visualization & Reporting")
    print("=" * 60 + "\n")
    
    # Initialize visualizer
    visualizer = TrafficVisualizer("data/captured/traffic_capture.csv")
    
    # Load data
    if not visualizer.load_data():
        return
    
    # Generate everything
    visualizer.generate_all_visuals()
    
    print("\n✓ Complete! Open the HTML report in your browser!\n")


if __name__ == "__main__":
    main()