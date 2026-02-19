# Network Traffic Analyzer

A Python-based network traffic analysis tool with machine learning anomaly detection capabilities.

## Project Overview

This tool captures network packets, analyzes traffic patterns, and uses machine learning to detect anomalous behavior. It integrates with network security scanners to provide comprehensive threat intelligence.

## Features (Planned - 3 Week Build)

**Core Packet Capture**
Real-time packet capture
Protocol analysis (TCP/UDP/ICMP)
Traffic statistics and reporting
CSV export for further analysis

**Machine Learning**
Feature engineering from packet data
Anomaly detection using Isolation Forest
Pattern recognition for common attacks
Threat scoring system

**Integration & Polish**
Integration with network scanner
HTML report generation
Visualization dashboard
Documentation and demo

## Installation

### 1. Prerequisites

**Windows:**
Python 3.8 or higher
Npcap (download from https://npcap.com/#download)
Install with "WinPcap API-compatible Mode" checked

**Mac/Linux:**
Python 3.8 or higher
libpcap (usually pre-installed)

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Permissions

**Windows:** Run VSCode as Administrator

**Mac/Linux:**
```bash
sudo python capture.py
# OR give Python packet capture permissions
```

## Usage

### Basic Packet Capture

```bash
python capture.py
```

This will:
1. Capture 50 packets from your network
2. Display packet information in real-time
3. Show summary statistics
4. Save results to `traffic_capture.csv`

### Understanding the Output

**Console Output:**
```
[Packet #1]
Time: 2024-02-19 14:30:45
Source: 192.168.1.100:52341
Destination: 142.250.80.78:443
Protocol: TCP
Length: 1420 bytes
```

**CSV Columns:**
- `timestamp`: When packet was captured
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port number
- `dst_port`: Destination port number
- `protocol`: Protocol type (TCP/UDP/ICMP)
- `length`: Packet size in bytes

## Project Structure

```
network-traffic-analyzer/
├── src/
│   ├── capture.py          # Packet capture module (Day 1 ✓)
│   ├── analyzer.py         # Traffic analysis (Week 1)
│   ├── ml_detector.py      # ML anomaly detection (Week 2)
│   ├── visualizer.py       # Graphs and reports (Week 3)
│   └── integrator.py       # Scanner integration (Week 3)
├── data/
│   ├── captured/           # Raw packet captures
│   ├── processed/          # Analyzed data
│   └── models/             # Trained ML models
├── reports/                # Generated reports
├── requirements.txt        # Dependencies
└── README.md              # This file
```

## Troubleshooting

### "Permission Denied" Error
- **Windows:** Run VSCode as Administrator
- **Mac/Linux:** Use `sudo` or configure packet capture permissions

### "No packets captured"
- Check if you have an active internet connection
- Try specifying a network interface
- Verify firewall isn't blocking packet capture

### Scapy import errors
- Reinstall: `pip uninstall scapy && pip install scapy`
- Windows: Ensure Npcap is installed correctly

## Next Steps

1. Run `capture.py` and verify packet capture works
2. Open the CSV file and examine the captured data
3. Next: Build `analyzer.py` to compute traffic statistics
4. Then: Add ML anomaly detection
5. Finally: Integrate with network scanner

## Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Network Protocol Basics](https://www.cloudflare.com/learning/network-layer/what-is-a-protocol/)
- [Wireshark for Visual Packet Analysis](https://www.wireshark.org/)

## Tech Stack

- **Python 3.8+**
- **Scapy** - Packet capture and manipulation
- **Pandas** - Data analysis
- **scikit-learn** - Machine learning
- **Matplotlib/Seaborn** - Visualization

## Author

Michael Hanson - Computer Science Student @ NJIT
Building towards a career in game development and security

## License

MIT License - Educational project
