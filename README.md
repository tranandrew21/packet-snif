[![Language](https://img.shields.io/badge/lang-Python-blue.svg)]() [![License](https://img.shields.io/badge/license-MIT-green.svg)]() [![Status](https://img.shields.io/badge/status-active-success.svg)]()

# Network Packet Sniffer (Scapy)
A Python-based tool that uses **Scapy** to capture and analyze live network traffic, filter packets by protocol, and log source/destination data to CSV for security analysis and anomaly detection.

## How to Run
```bash
pip install -r requirements.txt
python sniffer.py --proto dns --count 200 --csv out.csv --summary
```
