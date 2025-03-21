import argparse
import pyshark

def capture_traffic(interface, filter_expr, count):
    print(f"Starting capture on {interface}...")
    capture = pyshark.LiveCapture(interface=interface, display_filter=filter_expr)
    
    for packet in capture.sniff_continuously(packet_count=count):
        print_packet(packet)

def print_packet(packet):
    try:
        print("-------------------------------------------")
        print(f"Time: {packet.sniff_time}")
        print(f"Packet Length: {packet.length}")
        if hasattr(packet, 'ip'):
            print(f"Source IP: {packet.ip.src} -> Destination IP: {packet.ip.dst}")
        if hasattr(packet, 'tcp') or hasattr(packet, 'udp'):
            proto = 'TCP' if hasattr(packet, 'tcp') else 'UDP'
            port = packet.tcp.dstport if hasattr(packet, 'tcp') else packet.udp.dstport
            print(f"Protocol: {proto}, Destination Port: {port}")
        if hasattr(packet, 'http'):  # HTTP data
            print(f"HTTP Host: {packet.http.host}")
    except AttributeError:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CLI Network Traffic Monitor")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture on")
    parser.add_argument("-f", "--filter", default="", help="Wireshark display filter (e.g., 'tcp')")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture")
    
    args = parser.parse_args()
    capture_traffic(args.interface, args.filter, args.count)
