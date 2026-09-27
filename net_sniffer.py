from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import datetime

G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
R = "\033[0m"

def save_log(text):
    with open("traffic_data.log", "a") as f:
        f.write(text + "\n")

def process_packet(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "OTHER"
        payload = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            payload = str(pkt[TCP].payload)[:25]
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            payload = str(pkt[UDP].payload)[:25]

        t = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{t}] {G}{src_ip}{R} ---> {C}{dst_ip}{R} | PROTO: {Y}{protocol}{R} | DATA: {payload}"
        
        print(line)
        save_log(line)

print(f"{Y}[*] Sniffer running... Press Ctrl+C to exit.{R}\n")
print("-" * 65)

sniff(prn=process_packet, store=False)
