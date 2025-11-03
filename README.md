# DAT505 - Ethical Hacking
## Man-in-the-Middle Attack Lab

**ETHICAL USE ONLY**: This project is for educational purposes only. All attacks must be performed in a legally owned, isolated virtual lab environment. Unauthorized use is illegal.

---

## Overview

This repository contains a suite of Python-based tools developed to demonstrate a multi-stage Man-in-the-Middle (MITM) attack. The attack chain includes:

1.  **ARP Spoofing**: To achieve a MITM position between a victim and a gateway.
2.  **Traffic Analysis**: To passively capture and parse intercepted network traffic.
3.  **DNS Spoofing**: To actively redirect a victim to an attacker-controlled server.

---

## Setup

### Requirements
- Python 3.8+
- `python3-venv` and `python3-pip`
- Root/sudo privileges
- An isolated virtual network (Attacker, Victim, Gateway).

### Installation
Use a Python virtual environment to avoid conflicts with system packages.

```bash
# 1. Create a virtual environment
python3 -m venv venv

# 2. Activate the environment
source venv/bin/activate

# 3. Install all required dependencies
pip install -r requirements.txt
```

---

## Usage Workflow

All commands are run from the Attacker VM (`192.168.100.3`). Ensure your `venv` is active (`source venv/bin/activate`) for all Python commands.

### 1. ARP Spoofing (Task 1)
This script places the attacker between the victim (`192.168.100.2`) and the gateway (`192.168.100.1`).

```bash
# Usage: sudo python3 arp_spoof.py -t <victim_ip> -g <gateway_ip> -i <interface>
sudo python3 arp_spoof.py -t 192.168.100.2 -g 192.168.100.1 -i eth0 -v
```

### 2. Traffic Analysis (Task 2)
This process involves running the ARP spoofer, capturing traffic with `tcpdump`, and then parsing the results.

```bash
# In Terminal 1: Start the ARP spoofer
sudo python3 arp_spoof.py -t 192.168.100.2 -g 192.168.100.1 -i eth0

# In Terminal 2: Start the traffic capture
sudo tcpdump -i eth0 -w pcap_files/task2_capture.pcap

# --- On the Victim VM, generate HTTP and DNS traffic ---

# After capturing, stop both commands (Ctrl+C). Then parse the file:
python3 traffic_interceptor.py --parse -o pcap_files/task2_capture.pcap
```

### 3. DNS Spoofing (Task 3)
This is a three-part attack requiring 3 terminals on the Attacker VM. It redirects `www.real-site.lab` to the attacker.

**Prerequisite:** Add an `iptables` rule to block the real DNS response from being forwarded.
```bash
# Add the rule before starting the attack
sudo iptables -I FORWARD -p udp --dport 53 -j DROP

# IMPORTANT: Remove the rule after you are finished
sudo iptables -D FORWARD -p udp --dport 53 -j DROP
```

**Attack Execution:**

```bash
# In Terminal 1: Start the fake web server
sudo python3 fake_web_server.py

# In Terminal 2: Start the ARP spoofer
sudo python3 arp_spoof.py -t 192.168.100.2 -g 192.168.100.1 -i eth0

# In Terminal 3: Start the DNS spoofer
sudo python3 dns_spoof.py -i eth0 -c dns_spoof_config.json
```

---

## Author
Alexander Kvalvaag - DAT505 Ethical Hacking, 2025