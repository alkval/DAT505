# DAT505 - Network Security Assignment
## Man-in-the-Middle Attack Lab

**WARNING - ETHICAL USE ONLY**: Educational purposes only. Use in isolated lab environment.

## Overview

Implementation of three MitM attack tools:
1. **ARP Spoofing** - Position attacker between victim and gateway
2. **Traffic Capture & Analysis** - Intercept and analyze network traffic
3. **DNS Spoofing** - Redirect victims to attacker-controlled servers

## Setup

### Requirements
- Python 3.8+
- Root/sudo privileges
- Isolated virtual network (3 VMs recommended)

### Installation
```bash
pip3 install -r requirements.txt
```

## Usage

### 1. ARP Spoofing
```bash
sudo python3 arp_spoof.py -t <victim_ip> -g <gateway_ip> -i <interface>
```

### 2. Traffic Capture
```bash
# Capture traffic
sudo python3 traffic_interceptor.py -i <interface> -o output.pcap

# Parse PCAP file
sudo python3 traffic_interceptor.py --parse -o output.pcap
```

### 3. DNS Spoofing
```bash
# Edit dns_spoof_config.json with target domains and spoof IP
sudo python3 dns_spoof.py -i <interface> -c dns_spoof_config.json
```

### 4. Fake Web Server (Demo)
```bash
python3 fake_web_server.py -p 80
```

## Project Structure
```
DAT505/
├── arp_spoof.py              # Task 1: ARP spoofing
├── traffic_interceptor.py    # Task 2: Traffic analysis
├── dns_spoof.py              # Task 3: DNS spoofing
├── fake_web_server.py        # Demo server
├── dns_spoof_config.json     # DNS configuration
├── requirements.txt          # Dependencies
├── pcap_files/              # Network captures
├── evidence/                # Screenshots & analysis
└── report/                  # Assignment report
```

## Author
Alexander Kvalvaag - DAT505 Network Security Assignment, 2025
