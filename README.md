# Network Packet Sniffer

This is a Python script that captures and analyzes network packets using the Scapy library. It displays relevant information such as source and destination IP addresses, protocols, and payload data.

## Installation

1. Make sure you have Python installed on your system.

2. Install the required dependencies using pip:
   ```bash
   pip install scapy
   ```

3. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/your_username/network-packet-sniffer.git
   ```

4. Navigate to the project directory:
   ```bash
   cd network-packet-sniffer
   ```

## Usage

1. Modify the `interface` variable in the script to specify the name of the network interface you want to sniff on. Replace `"eth0"` with the appropriate interface name.

2. Run the script with elevated privileges using `sudo`:
   ```bash
   sudo python network_packet_sniffer.py
   ```

   You may need to enter your password to allow the script to access raw sockets for packet sniffing.

3. The script will start sniffing packets on the specified network interface and display relevant information for each captured packet.

## Example

```bash
sudo python network_packet_sniffer.py
Sniffing packets on interface eth0...
Source IP: 192.168.1.10 -> Destination IP: 8.8.8.8 | Protocol: TCP
Payload:
GET / HTTP/1.1
Host: www.example.com
...
==================================================
Source IP: 8.8.8.8 -> Destination IP: 192.168.1.10 | Protocol: TCP
Payload:
HTTP/1.1 200 OK
Content-Type: text/html
...
==================================================
```


