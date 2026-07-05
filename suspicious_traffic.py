# Detect Suspicious Traffic Patterns
import pyshark
from collections import defaultdict

# Path to the .pcap file
pcap_file = 'http_traffic.pcap'

def detect_suspicious_traffic(pcap_file):
    cap = pyshark.FileCapture(pcap_file)

    ip_traffic = defaultdict(int)

    print("Detecting suspicious traffic patterns...\n")

    for packet in cap:
        try:
            if 'IP' in packet:
                ip_traffic[packet.ip.dst] += 1
        except AttributeError as e:
            print(f"An error occurred: {e}")

    cap.close()

    # Define suspicious threshold
    threshold = 1000
    suspicious_ips = {ip: count for ip, count in ip_traffic.items() if count > threshold}

    if suspicious_ips:
        print("Suspicious Traffic Detected:")
        for ip, count in suspicious_ips.items():
            print(f"IP: {ip} - Packets: {count}")
    else:
        print("No suspicious traffic detected.")

if __name__ == "__main__":
    detect_suspicious_traffic(pcap_file)
    
    