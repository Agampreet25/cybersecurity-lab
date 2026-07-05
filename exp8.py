import pyshark
capture = pyshark.FileCapture('http_traffic.pcap')
print("HTTP Requests in the capture:\n")

for packet in capture:
    try:
        if 'HTTP' in packet:
            http_layer = packet.http

            # Extract Host and URI to build full URL
            host = http_layer.host
            uri = http_layer.request_uri

            full_url = f"http://{host}{uri}"
            print(full_url)

    except AttributeError:
        # Some packets may not contain the HTTP headers we're looking for
        pass

# Close capture to free memory
capture.close()
