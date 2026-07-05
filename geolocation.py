'''
import pyshark
import requests
from collections import defaultdict

# Path to the capture file
pcap_file = "http_traffic.pcap"

# API URL (Choose one: ipinfo.io or ipapi)
API_KEY = "YOUR_API_KEY"  # Replace with your key
API_URL = f"https://ipinfo.io/{{}}?token={API_KEY}"  # Using ipinfo.io

def get_geolocation(ip):
    """Fetch geolocation for a given IP address."""
    try:
        response = requests.get(API_URL.format(ip))
        data = response.json()
        return data.get("country", "Unknown"), data.get("region", "Unknown"), data.get("city", "Unknown")
    except Exception as e:
        print(f"Error fetching geolocation for {ip}: {e}")
        return "Unknown", "Unknown", "Unknown"

def extract_ip_geolocation(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")

    ip_locations = defaultdict(lambda: {"count": 0, "country": "", "region": "", "city": ""})

    for packet in cap:
        try:
            src_ip = packet.ip.src
            if src_ip.startswith("192.168") or src_ip.startswith("10.") or src_ip.startswith("172.16."):
                continue  # Ignore local IPs

            if src_ip not in ip_locations:
                country, region, city = get_geolocation(src_ip)
                ip_locations[src_ip]["country"] = country
                ip_locations[src_ip]["region"] = region
                ip_locations[src_ip]["city"] = city

            ip_locations[src_ip]["count"] += 1

        except AttributeError:
            continue

    cap.close()

    # Print IP Geolocation Summary
    print("\nIP Geolocation Summary:")
    print("=" * 80)
    print(f"{'IP Address':<20} {'Country':<15} {'Region':<15} {'City':<15} {'Count':<10}")
    print("=" * 80)
    for ip, info in ip_locations.items():
        print(f"{ip:<20} {info['country']:<15} {info['region']:<15} {info['city']:<15} {info['count']:<10}")

if __name__ == "__main__":
    extract_ip_geolocation(pcap_file)

'''
