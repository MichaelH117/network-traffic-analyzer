"""
Network Traffic Analyzer - Machine Learning Module
Week 2: Anomaly Detection using Isolation Forest
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import json
from datetime import datetime

class MLAnomalyDetector:
    def __init__(self, csv_file):
        """Initialize ML detector with captured traffic CSV"""
        self.csv_file = csv_file
        self.df = None
        self.features_df = None
        self.model = None
        self.scaler = StandardScaler()
        self.anomalies = []
        
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
    
    def engineer_features(self):
        """Extract ML features from raw packet data"""
        print("=" * 60)
        print("FEATURE ENGINEERING")
        print("=" * 60)
        print("\nExtracting features from packets...")
        
        features = []
        
        for idx, row in self.df.iterrows():
            # Basic packet features
            packet_features = {
                'packet_size': row['length'],
                'protocol_tcp': 1 if row['protocol'] == 'TCP' else 0,
                'protocol_udp': 1 if row['protocol'] == 'UDP' else 0,
                'protocol_icmp': 1 if row['protocol'] == 'ICMP' else 0,
            }
            
            # Port features (handle N/A ports)
            try:
                src_port = int(row['src_port']) if row['src_port'] != 'N/A' else 0
                dst_port = int(row['dst_port']) if row['dst_port'] != 'N/A' else 0
            except:
                src_port = 0
                dst_port = 0
            
            packet_features['src_port'] = src_port
            packet_features['dst_port'] = dst_port
            
            # Well-known port detection
            packet_features['is_well_known_port'] = 1 if dst_port < 1024 else 0
            packet_features['is_https'] = 1 if dst_port == 443 else 0
            packet_features['is_http'] = 1 if dst_port == 80 else 0
            packet_features['is_dns'] = 1 if dst_port == 53 else 0
            packet_features['is_ssh'] = 1 if dst_port == 22 else 0
            
            features.append(packet_features)
        
        self.features_df = pd.DataFrame(features)
        
        print(f"✓ Engineered {len(self.features_df.columns)} features:")
        for col in self.features_df.columns:
            print(f"  - {col}")
        
        print(f"\n✓ Feature matrix shape: {self.features_df.shape}")
        return self.features_df
    
    def add_contextual_features(self):
        """Add time-based and IP-based contextual features"""
        print("\nAdding contextual features...")
        
        # Add source IP features (connection frequency)
        src_ip_counts = self.df['src_ip'].value_counts()
        self.features_df['src_ip_frequency'] = self.df['src_ip'].map(src_ip_counts)
        
        # Add destination IP features
        dst_ip_counts = self.df['dst_ip'].value_counts()
        self.features_df['dst_ip_frequency'] = self.df['dst_ip'].map(dst_ip_counts)
        
        # Time-based features (if we have enough data)
        if len(self.df) > 1:
            # Calculate inter-packet time
            time_diffs = self.df['timestamp'].diff().dt.total_seconds().fillna(0)
            self.features_df['time_since_last_packet'] = time_diffs
        else:
            self.features_df['time_since_last_packet'] = 0
        
        # Port diversity (how many unique ports this IP has accessed)
        port_diversity = self.df.groupby('src_ip')['dst_port'].nunique()
        self.features_df['port_diversity'] = self.df['src_ip'].map(port_diversity)
        
        print(f"✓ Added 4 contextual features")
        print(f"✓ Total features: {len(self.features_df.columns)}")
        
        return self.features_df
    
    def train_model(self, contamination=0.1):
        """Train Isolation Forest model on the traffic data"""
        print("\n" + "=" * 60)
        print("TRAINING ISOLATION FOREST MODEL")
        print("=" * 60)
        
        if self.features_df is None:
            print("Error: Features not engineered yet!")
            return False
        
        print(f"\nModel Configuration:")
        print(f"  Algorithm: Isolation Forest")
        print(f"  Contamination: {contamination} ({contamination*100}% expected anomalies)")
        print(f"  Features: {len(self.features_df.columns)}")
        print(f"  Training samples: {len(self.features_df)}")
        
        # Scale features
        print("\nScaling features...")
        X_scaled = self.scaler.fit_transform(self.features_df)
        
        # Train Isolation Forest
        print("Training model...")
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        self.model.fit(X_scaled)
        
        print("✓ Model training complete!")
        
        # Predict on training data
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        # -1 = anomaly, 1 = normal
        n_anomalies = (predictions == -1).sum()
        n_normal = (predictions == 1).sum()
        
        print(f"\nTraining Results:")
        print(f"  Normal traffic: {n_normal} packets ({n_normal/len(self.df)*100:.1f}%)")
        print(f"  Anomalies detected: {n_anomalies} packets ({n_anomalies/len(self.df)*100:.1f}%)")
        
        # Store results
        self.df['is_anomaly'] = predictions == -1
        self.df['anomaly_score'] = scores
        
        return True
    
    def analyze_anomalies(self):
        """Analyze detected anomalies in detail"""
        print("\n" + "=" * 60)
        print("ANOMALY ANALYSIS")
        print("=" * 60)
        
        anomalies = self.df[self.df['is_anomaly'] == True]
        
        if len(anomalies) == 0:
            print("\n✓ No anomalies detected - all traffic appears normal!")
            return
        
        print(f"\n⚠️  Detected {len(anomalies)} anomalous packets:")
        print("=" * 60)
        
        for idx, (i, row) in enumerate(anomalies.iterrows(), 1):
            print(f"\n[Anomaly #{idx}]")
            print(f"Timestamp: {row['timestamp']}")
            print(f"Source: {row['src_ip']}:{row['src_port']}")
            print(f"Destination: {row['dst_ip']}:{row['dst_port']}")
            print(f"Protocol: {row['protocol']}")
            print(f"Size: {row['length']} bytes")
            print(f"Anomaly Score: {row['anomaly_score']:.4f} (lower = more anomalous)")
            
            # Analyze why it's anomalous
            reasons = []
            
            # Check packet size
            mean_size = self.df['length'].mean()
            std_size = self.df['length'].std()
            if row['length'] > mean_size + (2 * std_size):
                reasons.append(f"Unusually large packet ({row['length']} vs avg {mean_size:.0f})")
            elif row['length'] < mean_size - (2 * std_size):
                reasons.append(f"Unusually small packet ({row['length']} vs avg {mean_size:.0f})")
            
            # Check protocol
            protocol_dist = self.df['protocol'].value_counts(normalize=True)
            if protocol_dist[row['protocol']] < 0.1:
                reasons.append(f"Rare protocol ({row['protocol']})")
            
            # Check port
            if row['dst_port'] != 'N/A':
                try:
                    port = int(row['dst_port'])
                    if port > 49152:  # Ephemeral ports
                        reasons.append(f"Unusual high port number ({port})")
                except:
                    pass
            
            if reasons:
                print(f"Possible reasons:")
                for reason in reasons:
                    print(f"  • {reason}")
            
            print("-" * 60)
        
        # Store anomalies for export
        self.anomalies = anomalies.to_dict('records')
        
        return anomalies
    
    def classify_threats(self):
        """Classify anomalies into threat categories"""
        print("\n" + "=" * 60)
        print("THREAT CLASSIFICATION")
        print("=" * 60)
        
        if not self.df['is_anomaly'].any():
            print("\n✓ No threats to classify")
            return
        
        anomalies = self.df[self.df['is_anomaly'] == True].copy()
        
        threat_categories = {
            'Port Scan': [],
            'Data Exfiltration': [],
            'DDoS Indicator': [],
            'Unusual Protocol': [],
            'Unknown': []
        }
        
        for idx, row in anomalies.iterrows():
            classified = False
            
            # Port scan detection
            src_ip = row['src_ip']
            ports_accessed = self.df[self.df['src_ip'] == src_ip]['dst_port'].nunique()
            if ports_accessed >= 5:
                threat_categories['Port Scan'].append(row)
                classified = True
            
            # Large data transfer (potential exfiltration)
            if row['length'] > self.df['length'].quantile(0.95):
                threat_categories['Data Exfiltration'].append(row)
                classified = True
            
            # High frequency (DDoS)
            src_count = len(self.df[self.df['src_ip'] == src_ip])
            if src_count > len(self.df) * 0.3:
                threat_categories['DDoS Indicator'].append(row)
                classified = True
            
            # Unusual protocol
            if row['protocol'] not in ['TCP', 'UDP']:
                threat_categories['Unusual Protocol'].append(row)
                classified = True
            
            if not classified:
                threat_categories['Unknown'].append(row)
        
        # Display results
        print("\nThreat Distribution:")
        for category, threats in threat_categories.items():
            if len(threats) > 0:
                print(f"\n  {category}: {len(threats)} instances")
                for threat in threats[:3]:  # Show first 3
                    print(f"    • {threat['src_ip']} → {threat['dst_ip']} ({threat['protocol']})")
                if len(threats) > 3:
                    print(f"    ... and {len(threats)-3} more")
        
        return threat_categories
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n" + "=" * 70)
        print("ML SECURITY ANALYSIS REPORT")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        if self.df is None:
            print("No data loaded!")
            return
        
        # Overall statistics
        total_packets = len(self.df)
        n_anomalies = self.df['is_anomaly'].sum()
        anomaly_rate = (n_anomalies / total_packets) * 100
        
        print(f"\nOVERALL SECURITY STATUS:")
        print(f"  Total Packets Analyzed: {total_packets}")
        print(f"  Normal Traffic: {total_packets - n_anomalies} ({100-anomaly_rate:.1f}%)")
        print(f"  Anomalies Detected: {n_anomalies} ({anomaly_rate:.1f}%)")
        
        if n_anomalies == 0:
            print(f"\n✓ SECURITY STATUS: NORMAL")
            print("  All traffic patterns appear legitimate")
        elif anomaly_rate < 10:
            print(f"\n⚠️  SECURITY STATUS: LOW RISK")
            print(f"  Small number of anomalies detected - recommend investigation")
        elif anomaly_rate < 25:
            print(f"\n⚠️  SECURITY STATUS: MEDIUM RISK")
            print(f"  Significant anomalies detected - immediate review recommended")
        else:
            print(f"\n🚨 SECURITY STATUS: HIGH RISK")
            print(f"  High anomaly rate - potential security incident")
        
        # Top risks
        if n_anomalies > 0:
            print(f"\nTOP SECURITY CONCERNS:")
            anomalies = self.df[self.df['is_anomaly'] == True].sort_values('anomaly_score')
            
            for idx, (i, row) in enumerate(anomalies.head(5).iterrows(), 1):
                print(f"\n  {idx}. {row['src_ip']} → {row['dst_ip']}")
                print(f"     Protocol: {row['protocol']} | Port: {row['dst_port']}")
                print(f"     Risk Score: {abs(row['anomaly_score']):.4f}")
        
        print("\n" + "=" * 70)
    
    def save_model(self, model_path="data/models/anomaly_detector.pkl"):
        """Save trained model and scaler"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': list(self.features_df.columns)
            }
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            print(f"\n✓ Model saved to {model_path}")
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def export_results(self, output_path="data/processed/ml_analysis.json"):
        """Export ML analysis results to JSON"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'total_packets': len(self.df),
                'anomalies_detected': int(self.df['is_anomaly'].sum()),
                'anomaly_rate': float((self.df['is_anomaly'].sum() / len(self.df)) * 100),
                'anomalies': []
            }
            
            # Add anomaly details
            anomalies = self.df[self.df['is_anomaly'] == True]
            for idx, row in anomalies.iterrows():
                results['anomalies'].append({
                    'timestamp': str(row['timestamp']),
                    'src_ip': row['src_ip'],
                    'dst_ip': row['dst_ip'],
                    'src_port': str(row['src_port']),
                    'dst_port': str(row['dst_port']),
                    'protocol': row['protocol'],
                    'length': int(row['length']),
                    'anomaly_score': float(row['anomaly_score'])
                })
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"✓ ML results exported to {output_path}")
        except Exception as e:
            print(f"Error exporting results: {e}")


def main():
    """Main function to run ML anomaly detection"""
    
    print("\n" + "=" * 60)
    print("NETWORK TRAFFIC ANALYZER v1.0")
    print("Week 2: Machine Learning Anomaly Detection")
    print("=" * 60 + "\n")
    
    # Initialize detector
    detector = MLAnomalyDetector("data/captured/traffic_capture.csv")
    
    # Load data
    if not detector.load_data():
        return
    
    # Feature engineering
    detector.engineer_features()
    detector.add_contextual_features()
    
    # Train model
    detector.train_model(contamination=0.15)  # Expect 15% anomalies
    
    # Analyze results
    detector.analyze_anomalies()
    detector.classify_threats()
    detector.generate_security_report()
    
    # Save model and results
    detector.save_model()
    detector.export_results()
    
    print("\n✓ ML Analysis complete!")
    print("Next: Integration with network scanner\n")


if __name__ == "__main__":
    main()