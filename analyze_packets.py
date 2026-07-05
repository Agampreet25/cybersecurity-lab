#	Python Program to Analyze Data:
import pyshark
# Path to the .pcap file
pcap_file = 'http_traffic.pcap'
# Open the capture file
cap = pyshark.FileCapture(pcap_file)
# Print basic information about the packets
for packet in cap:
    try:
        # Print packet number and some summary information
        print(f"Packet Number: {packet.number}")
        print(f"Packet Length: {packet.length}")
        print(f"Packet Protocols: {packet.highest_layer}")
        print(f"Packet Info: {packet.info}")
        print("-" * 50)
    except AttributeError as e:
        # Handle cases where some attributes might not be present
        print(f"An error occurred: {e}")

# Close the capture file
cap.close()
