# NETWORK PACKET ANALYZER
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet, protocol_filter):
    if IP not in packet:
        return  # Skip non-IP packets

    proto = packet[IP].proto

    if protocol_filter != 'all':
        if protocol_filter == 'tcp' and TCP not in packet:
            return
        elif protocol_filter == 'udp' and UDP not in packet:
            return
        elif protocol_filter == 'icmp' and ICMP not in packet:
            return

    print("=" * 80)
    print(f"Time: {datetime.now()}")

    ip_layer = packet[IP]
    print(f"[+] Source IP      : {ip_layer.src}")
    print(f"[+] Destination IP : {ip_layer.dst}")

    if proto == 6:
        print("[+] Protocol       : TCP")
    elif proto == 17:
        print("[+] Protocol       : UDP")
    elif proto == 1:
        print("[+] Protocol       : ICMP")
    else:
        print(f"[+] Protocol       : Other ({proto})")

    if TCP in packet or UDP in packet:
        print(f"[+] Source Port    : {packet.sport}")
        print(f"[+] Destination Port: {packet.dport}")

    if packet.haslayer(Raw := getattr(packet, 'Raw', None)):
        payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
        print(f"[+] Payload        :\n{payload}")
    else:
        print("[+] Payload        : <No Payload>")

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer (Educational Use Only)")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "all"], default="all", help="Protocol filter")

    args = parser.parse_args()

    print(f"\n[+] Starting packet sniffing on {args.interface} (Protocol: {args.protocol}, Count: {args.count or '∞'})\nPress Ctrl+C to stop.\n")
    
    try:
        sniff(
            iface=args.interface,
            prn=lambda pkt: packet_callback(pkt, args.protocol),
            store=False,
            count=args.count if args.count > 0 else 0
        )
    except PermissionError:
        print("[-] Permission denied. Try running with sudo/root privileges.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
