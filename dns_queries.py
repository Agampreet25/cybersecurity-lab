import pyshark

pcap_file = "dnsss.pcap"

def analyze_dns(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="dns")

    dns_queries = {}
    dns_responses = {}

    print("Analyzing DNS packets...\n")

    for packet in cap:
        try:
            if 'DNS' in packet:
                # Check if it's a DNS query
                if hasattr(packet.dns, 'qry_name'):
                    domain = packet.dns.qry_name
                    dns_queries[domain] = dns_queries.get(domain, 0) + 1
                    print(f"DNS Query: {domain}")

                # Check if it's a DNS response
                if hasattr(packet.dns, 'a'):
                    domain = packet.dns.qry_name
                    resolved_ip = packet.dns.a
                    dns_responses[domain] = resolved_ip
                    print(f"DNS Response: {domain} -> {resolved_ip}")

        except AttributeError:
            continue  # Skip packets with missing attributes

    cap.close()

    print("\nDNS Query Summary:")
    for domain, count in dns_queries.items():
        print(f"{domain}: {count} queries")

    print("\nDNS Response Summary:")
    for domain, ip in dns_responses.items():
        print(f"{domain} resolved to {ip}")

if __name__ == "__main__":
    analyze_dns(pcap_file)
