#!/usr/bin/env python3
"""Traffic Interceptor & Analyzer - DAT505"""

import argparse
import sys
import signal
import csv
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, conf

class TrafficInterceptor:
    def __init__(self, interface, output_file, duration=None):
        self.interface = interface
        self.output_file = output_file
        self.duration = duration
        self.packets = []
        conf.iface = interface
        conf.verb = 0
    
    def packet_callback(self, packet):
        self.packets.append(packet)
    
    def start_capture(self):
        print(f"Capturing on {self.interface}...")
        try:
            sniff(iface=self.interface, prn=self.packet_callback, 
                  timeout=self.duration, store=False)
        except KeyboardInterrupt:
            pass
        self.save_capture()
    
    def save_capture(self):
        wrpcap(self.output_file, self.packets)
        print(f"Saved {len(self.packets)} packets to {self.output_file}")

class TrafficAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.urls = []
        self.dns_queries = []
    
    def load_pcap(self):
        self.packets = rdpcap(self.pcap_file)
    
    def extract_http_info(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith(('GET ', 'POST ')):
                lines = payload.split('\r\n')
                if len(lines) > 1:
                    method = lines[0].split()[0]
                    path = lines[0].split()[1]
                    host = next((l.split(': ')[1] for l in lines if l.startswith('Host:')), '')
                    if host:
                        url = f"http://{host}{path}"
                        self.urls.append({
                            'method': method,
                            'url': url,
                            'src_ip': packet[IP].src,
                            'dst_ip': packet[IP].dst
                        })
    
    def extract_dns_info(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            self.dns_queries.append({
                'src_ip': packet[IP].src,
                'domain': qname
            })
    
    def analyze(self):
        self.load_pcap()
        print(f"Analyzing {len(self.packets)} packets...")
        
        for packet in self.packets:
            if packet.haslayer(IP):
                self.extract_http_info(packet)
                self.extract_dns_info(packet)
        
        self.save_results()
    
    def save_results(self):
        if self.urls:
            urls_file = "evidence/urls_extracted.csv"
            with open(urls_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['method', 'url', 'src_ip', 'dst_ip'])
                writer.writeheader()
                writer.writerows(self.urls)
            print(f"Saved {len(self.urls)} URLs to {urls_file}")
        
        if self.dns_queries:
            dns_file = "evidence/dns_queries.log"
            with open(dns_file, 'w') as f:
                for query in self.dns_queries:
                    f.write(f"{query['src_ip']} -> {query['domain']}\n")
            print(f"Saved {len(self.dns_queries)} DNS queries to {dns_file}")

def main():
    parser = argparse.ArgumentParser(description="Traffic Interceptor & Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-o", "--output", required=True, help="Output PCAP file")
    parser.add_argument("-d", "--duration", type=int, help="Capture duration (seconds)")
    parser.add_argument("--parse", action="store_true", help="Parse existing PCAP")
    args = parser.parse_args()
    
    if args.parse:
        analyzer = TrafficAnalyzer(args.output)
        analyzer.analyze()
    else:
        if not args.interface:
            print("Error: -i/--interface required for capture")
            sys.exit(1)
        interceptor = TrafficInterceptor(args.interface, args.output, args.duration)
        
        def signal_handler(sig, frame):
            interceptor.save_capture()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        interceptor.start_capture()

if __name__ == "__main__":
    main()
