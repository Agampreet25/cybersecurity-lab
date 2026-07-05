import pyshark
from collections import defaultdict

# Path to the capture file
pcap_file = "http_traffic.pcap"

def analyze_tcp_flows(pcap_file):
    # Open capture file
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp")

    # Dictionary to store TCP flows
    tcp_flows = defaultdict(lambda: {"packet_count": 0, "total_bytes": 0})

    # Iterate over packets
    for packet in cap:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            packet_size = int(packet.length)

            # Define unique TCP flow key
            flow_key = (src_ip, src_port, dst_ip, dst_port)

            # Update counts
            tcp_flows[flow_key]["packet_count"] += 1
            tcp_flows[flow_key]["total_bytes"] += packet_size

        except AttributeError:
            continue

    cap.close()

    # Print TCP flow summary
    print("\nTCP Flow Summary:")
    print("=" * 80)
    print(f"{'Source IP':<20} {'Dest IP':<20} {'Src Port':<10} {'Dst Port':<10} {'Packets':<10} {'Bytes':<10}")
    print("=" * 80)
    for (src_ip, src_port, dst_ip, dst_port), stats in tcp_flows.items():
        print(f"{src_ip:<20} {dst_ip:<20} {src_port:<10} {dst_port:<10} {stats['packet_count']:<10} {stats['total_bytes']:<10}")

if __name__ == "__main__":
    analyze_tcp_flows(pcap_file)
