from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_analyzer(packet):
    print("=" * 50)

    if packet.haslayer(IP):
        ip = packet[IP]
        print("Source IP      :", ip.src)
        print("Destination IP :", ip.dst)

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol       : TCP")
            print("Source Port    :", tcp.sport)
            print("Destination Port:", tcp.dport)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol       : UDP")
            print("Source Port    :", udp.sport)
            print("Destination Port:", udp.dport)

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        if packet.haslayer(Raw):
            print("Payload        :", packet[Raw].load)

    else:
        print("Non-IP Packet")

print("Starting packet capture... Press CTRL+C to stop.")
sniff(prn=packet_analyzer, count=10)
