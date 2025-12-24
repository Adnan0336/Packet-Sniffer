# Packet-Sniffer
A Packet Sniffer is a network analysis tool that captures and analyzes network packets in real time.
This project demonstrates how data packets travel across a network and helps in understanding network protocols, traffic flow, and potential security threats.

The packet sniffer captures raw packets, extracts key information such as source IP, destination IP, protocol type, and payload data, and displays them in a readable format.
It is useful for learning networking concepts, cybersecurity analysis, and traffic monitoring.

🚀 Features

📡 Capture live network packets

🌐 Identify source and destination IP addresses

🔐 Detect protocols (TCP, UDP, ICMP, etc.)

📊 Analyze packet headers and payloads

🛡️ Useful for cybersecurity learning and network troubleshooting

🛠️ Technologies Used

Python

Socket Programming

Networking Protocols

(Optional: Scapy / Raw Sockets depending on implementation)

📂 Project Structure
packet-sniffer/
│
├── packet_sniffer.py      # Main packet sniffing script
├── README.md              # Project documentation
├── LICENSE                # License file
└── requirements.txt       # Dependencies (if any)

⚙️ How It Works

The program listens to the network interface.

It captures raw packets from the network.

Packet headers are decoded to extract:

Source IP

Destination IP

Protocol type

Packet details are displayed on the terminal for analysis.

▶️ Usage
python packet_sniffer.py


⚠️ Note:

Run with administrator/root privileges

Use only on authorized networks

🎯 Use Cases

Network traffic analysis

Learning TCP/IP and OSI model

Detecting suspicious or malicious traffic

Cybersecurity lab practice

⚠️ Disclaimer

This project is intended for educational purposes only.
Unauthorized packet sniffing on networks without permission is illegal and unethical.
The author is not responsible for misuse of this tool.
