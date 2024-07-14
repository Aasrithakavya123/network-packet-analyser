from scapy.all import sniff, get_if_list, IP, TCP, UDP

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {str(tcp_layer.payload)}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {str(udp_layer.payload)}")
        else:
            print(f"Protocol: Other")
        print("\n")

def start_sniffing(interface=None):
    print("Starting packet sniffer...")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    # List available network interfaces
    print("Available network interfaces:")
    interfaces = get_if_list()
    for iface in interfaces:
        print(iface)
    
    # Replace 'Wi-Fi' with your network interface name from the list
    start_sniffing(interface="Wi-Fi")
