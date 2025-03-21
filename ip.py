import argparse
import requests
import socket


def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        dns = (f"🔍 DNS: {host[0]}")
        return dns
    except socket.herror:
        dns = print("❌ No hostname found")
        return dns

def check_vpn_or_proxy(ip):
    url = f"http://ipinfo.io/{ip}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if 'vpn' in data.get('hostname', '').lower() or 'proxy' in data.get('hostname', '').lower():
            result = (f"🚨 VPN or Proxy detected for IP {ip}")
        else:
            result = (f"✅ No VPN or Proxy detected for IP {ip}")
    else:
        result = (f"❌ Error: {response.status_code}")
    return result




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


parser = argparse.ArgumentParser(description="🌍 IP Lookup Tool using ipinfo.io")
parser.add_argument('ip', help="IP address to lookup")
args = parser.parse_args()

lookup_ip(args.ip)