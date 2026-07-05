import pyshark
pcap_file = 'http_traffic.pcap'
def analyze_dns(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    dns_requests = 0
    dns_responses = 0
    print("Analyzing DNS packets...\n")
    for packet in cap:
        try:
            if 'DNS' in packet:
                if 'Response' in packet.dns.flags:
                    dns_responses += 1
                    print(f"DNS Response - Query: {packet.dns.qry_name}, Answer: {packet.dns.a}")
                else:
                    dns_requests += 1
                    print(f"DNS Request - Query: {packet.dns.qry_name}")
        except AttributeError as e:
            print(f"An error occurred: {e}")
    cap.close()
    print("\nDNS Analysis Summary:")
    print(f"Total DNS Requests: {dns_requests}")
    print(f"Total DNS Responses: {dns_responses}")
if __name__ == "__main__":
    analyze_dns(pcap_file)
    