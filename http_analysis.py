import pyshark

# Path to the .pcap file
pcap_file = 'http_traffic.pcap'

def analyze_packets(pcap_file):
    # Open the capture file
    cap = pyshark.FileCapture(pcap_file)
    
    # Initialize counters for different types of packets
    http_count = 0
    tcp_count = 0
    ip_count = 0
    
    print("Analyzing packets...\n")
    
    # Iterate over packets
    for packet in cap:
        try:
            # Check for HTTP packets
            if 'HTTP' in packet:
                http_count += 1
                print(f"HTTP Packet - {packet.http.method} request to {packet.http.host}")
            
            # Check for TCP packets
            if 'TCP' in packet:
                tcp_count += 1
                print(f"TCP Packet - Source Port: {packet.tcp.srcport}, Destination Port: {packet.tcp.dstport}")
            
            # Check for IP packets
            if 'IP' in packet:
                ip_count += 1
                print(f"IP Packet - Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")
            
        except AttributeError as e:
            # Handle cases where some attributes might not be present
            print(f"An error occurred: {e}")

    # Close the capture file
    cap.close()
    
    # Print summary of the analysis
    print("\nAnalysis Summary:")
    print(f"Total HTTP Packets: {http_count}")
    print(f"Total TCP Packets: {tcp_count}")
    print(f"Total IP Packets: {ip_count}")

if __name__ == "__main__":
    analyze_packets(pcap_file)
    