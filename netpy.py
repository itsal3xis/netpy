import argparse
import pyshark
from rich.console import Console
from rich.table import Table
from rich.live import Live
import json

# Store captured packets in a JSON file
captured_packets_file = "captured_packets.json"

def capture_traffic(interface, filter_expr, count):
    global captured_packets
    console = Console()
    table = Table(title="NetPY Traffic Monitoring by itsal3xis")
    table.add_column("Packet ID", justify="center", style="cyan")
    table.add_column("Src IP", justify="center", style="magenta")
    table.add_column("Dst IP", justify="center", style="magenta")
    table.add_column("Protocol", justify="center", style="green")
    table.add_column("Port", justify="center", style="yellow")
    table.add_column("Length", justify="center", style="yellow")
    table.add_column("Source MAC", justify="center", style="blue")
    table.add_column("Destination MAC", justify="center", style="blue")
    table.add_column("TCP/UDP Details", justify="center", style="yellow")


    console.print(f"[bold green]Starting capture on {interface}...[/bold green]\n")
    capture = pyshark.LiveCapture(interface=interface, display_filter=filter_expr)
    
    packet_id = 1
    captured_packets = {}  # Initialize empty dictionary for captured packets
    with Live(table, console=console, refresh_per_second=2):
        for packet in capture.sniff_continuously(packet_count=count):
            packet_info = extract_packet_info(packet)
            if packet_info:
                captured_packets[packet_id] = packet_info  # Store packet by ID
                table.add_row(str(packet_id), *packet_info[1:])  # Display packet ID only
                packet_id += 1

    # Save the captured packets to a JSON file
    with open(captured_packets_file, "w") as f:
        json.dump(captured_packets, f)
    console.print(f"[bold green]Captured packets saved to {captured_packets_file}[/bold green]")

def extract_packet_info(packet):
    try:
        time = str(packet.sniff_time)
        src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
        protocol = "TCP" if hasattr(packet, 'tcp') else ("UDP" if hasattr(packet, 'udp') else "Other")
        port = packet.tcp.dstport if hasattr(packet, 'tcp') else (packet.udp.dstport if hasattr(packet, 'udp') else "N/A")
        length = packet.length  # Total packet length
        src_mac = packet.eth.src if hasattr(packet, 'eth') else "N/A"
        dst_mac = packet.eth.dst if hasattr(packet, 'eth') else "N/A"
        
        # Additional TCP/UDP details
        if hasattr(packet, 'tcp'):
            tcp_flags = packet.tcp.flags
            seq_num = packet.tcp.seq
            ack_num = packet.tcp.ack
            tcp_details = f"Flags: {tcp_flags} Seq: {seq_num} Ack: {ack_num}"
        else:
            tcp_details = "N/A"

        if hasattr(packet, 'udp'):
            udp_length = packet.udp.length
        else:
            udp_length = "N/A"

        return [time, src_ip, dst_ip, protocol, str(port), str(length), src_mac, dst_mac, tcp_details if hasattr(packet, 'tcp') else udp_length]
    except AttributeError:
        return None

def view_packet_details(packet_id):
    try:
        with open(captured_packets_file, "r") as f:
            captured_packets = json.load(f)
        
        if str(packet_id) in captured_packets:
            packet_info = captured_packets[str(packet_id)]
            console = Console()
            console.print(f"[bold yellow]Details for Packet ID {packet_id}[/bold yellow]")
            console.print(f"Time: {packet_info[0]}")
            console.print(f"Source IP: {packet_info[1]}")
            console.print(f"Destination IP: {packet_info[2]}")
            console.print(f"Protocol: {packet_info[3]}")
            console.print(f"Port: {packet_info[4]}")
            console.print(f"Length: {packet_info[5]}")
            console.print(f"Source MAC: {packet_info[6]}")
            console.print(f"Destination MAC: {packet_info[7]}")
            console.print(f"TCP/UDP Details: {packet_info[8]}")
        else:
            print(f"Packet ID {packet_id} not found.")
    except FileNotFoundError:
        print("No captured packets found. Please capture packets first.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CLI Network Traffic Monitor")
    subparsers = parser.add_subparsers(dest="command")

    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Capture network traffic")
    capture_parser.add_argument("-i", "--interface", required=True, help="Network interface to capture on")
    capture_parser.add_argument("-f", "--filter", default="", help="Wireshark display filter (e.g., 'tcp')")
    capture_parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture")

    # View details command
    view_parser = subparsers.add_parser("view", help="View details of a captured packet")
    view_parser.add_argument("packet_id", type=int, help="Packet ID to view")

    args = parser.parse_args()

    if args.command == "capture":
        capture_traffic(args.interface, args.filter, args.count)
    
    if args.command == "view":
        view_packet_details(args.packet_id)