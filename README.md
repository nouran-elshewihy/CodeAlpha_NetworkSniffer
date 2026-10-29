# Network Sniffer & Traffic Analyzer

A Python script built with Scapy to capture, filter, and log live network traffic.

## Details & Implementation

- **Packet Capture:** Uses Scapy's `sniff()` function to intercept live network traffic.
- **Protocol Parsing:** Extracts source/destination IPs and identifies TCP/UDP layers.
- **Data Logging:** Automatically dumps captured packet data into `traffic_data.log` with timestamps.
- **Terminal Output:** Color-coded terminal display using ANSI escape sequences for easy monitoring
