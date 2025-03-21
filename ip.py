import argparse
import requests
import socket
import json

# File where captured packets are stored
captured_packets_file = "captured_packets.json"

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        dns = f"🔍 DNS: {host[0]}"
        return dns
    except socket.herror:
        return "❌ No hostname found"

def check_vpn_or_proxy(ip):
    url = f"http://ipinfo.io/{ip}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if 'vpn' in data.get('hostname', '').lower() or 'proxy' in data.get('hostname', '').lower():
            return f"🚨 VPN or Proxy detected for IP {ip}"
        else:
            return f"✅ No VPN or Proxy detected for IP {ip}"
    else:
        return f"❌ Error: {response.status_code}"

def lookup_ip(ip):
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        if response.status_code == 200:
            data = response.json()
            vpn = check_vpn_or_proxy(ip)
            dns = reverse_dns(ip)
            print(f"🌍 IP: {data.get('ip')}")
            print(dns)
            print(f"📍 Location: {data.get('city')}, {data.get('region')}, {data.get('country')}")
            print(f"📶 ISP: {data.get('org')}")
            print(f"📡 Coordinates: {data.get('loc')}")
            print(f"⏰ Timezone: {data.get('timezone')}")
            print(vpn)
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Request Error: {e}")

def get_packet_info(packet_id, field):
    try:
        with open(captured_packets_file, "r") as f:
            captured_packets = json.load(f)
        packet_id_str = str(packet_id)  # Convert packet_id to string
        if packet_id_str in captured_packets:
            packet_info = captured_packets[packet_id_str]  # Access the packet by string ID
            if field == 'src':
                return packet_info[1]  # Source IP
            elif field == 'dst':
                return packet_info[2]  # Destination IP
            else:
                print("❌ Invalid field. Use 'src' or 'dst'.")
                return None
        else:
            print(f"❌ Packet ID {packet_id} not found.")
            return None
    except FileNotFoundError:
        print("❌ No captured packets found. Please capture packets first.")
        return None





def main():
    parser = argparse.ArgumentParser(description="🌍 IP Lookup Tool using ipinfo.io")
    parser.add_argument('ip', nargs='?', help="IP address to lookup (used if no packet ID is provided)")
    parser.add_argument('-p', '--packet', type=int, help="Packet ID to lookup")
    parser.add_argument('-s', '--src', action='store_true', help="Lookup source IP from the packet")
    parser.add_argument('-d', '--dst', action='store_true', help="Lookup destination IP from the packet")

    args = parser.parse_args()

    if args.packet:
        if args.src:
            ip = get_packet_info(args.packet, 'src')
        elif args.dst:
            ip = get_packet_info(args.packet, 'dst')
        else:
            print("❌ You must specify --src or --dst to lookup IP.")
            return
        
        if ip:
            lookup_ip(ip)
    elif args.ip:
        lookup_ip(args.ip)
    else:
        print("❌ Please provide an IP address or a packet ID with --src or --dst.")

if __name__ == "__main__":
    main()
