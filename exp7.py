import pyshark
capture = pyshark.FileCapture('http_traffic.pcap')
# Set to store unique IPs
ip_addresses = set()
# Loop through packets and extract IPs
for packet in capture:
    try:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ip_addresses.add(src_ip)
            ip_addresses.add(dst_ip)
    except AttributeError:
        # Some packets might not have IP layer (e.g., ARP), skip those
        pass

# Close capture file
capture.close()
# Print all unique IP addresses
print("IP addresses found in the capture:")
for ip in ip_addresses:
    print(ip)
