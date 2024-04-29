import scapy.all as scapy


def sniff_packets(interface):
    """
    Sniff packets on the specified network interface.

    Args:
    - interface (str): Name of the network interface to sniff on.
    """
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    """
    Process each captured packet and display relevant information.

    Args:
    - packet (scapy.packet): Captured network packet.
    """
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None

        print(f"Source IP: {source_ip} -> Destination IP: {destination_ip} | Protocol: {protocol}")

        if payload:
            print("Payload:")
            print(payload)
            print("=" * 50)


# Example usage:
interface = "wlan0"  # Change this to the name of your network interface
print(f"Sniffing packets on interface {interface}...")
sniff_packets(interface)
