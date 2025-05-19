# PRODIGY_CS_05
# 🔍 Network Packet Analyzer

A lightweight and educational Python-based network packet analyzer built using [Scapy](https://scapy.net). It allows users to sniff network traffic in real-time, displaying source/destination IPs, ports, protocol types, and payloads. Ideal for learning network protocol behavior or debugging network issues.

---

## ⚠️ Disclaimer

> 🚨 **For Educational Use Only**  
This tool is intended **strictly for ethical and educational purposes** such as traffic analysis, debugging, and cybersecurity learning. Unauthorized use on networks without consent may violate privacy and legal regulations.

---

## 📌 Features

- 📡 Real-time packet sniffing
- 🌐 Protocol filtering: TCP, UDP, ICMP, or all
- 🧾 Displays:
  - Timestamp
  - Source and destination IP
  - Protocol type
  - Ports (if applicable)
  - Packet payload (if present)
- 🎯 Customizable interface and packet count

---

## 🛠️ Requirements

- Python 3.x
- [Scapy](https://scapy.net)

Install Scapy:

```bash
pip install scapy
```
## 🚀 Usage
❗ Run the script with sudo/root permissions to access network interfaces.

```bash
sudo python packet_sniffer.py -i <interface> [-c <count>] [-p <protocol>]
```
## 💡 Example
```bash
sudo python packet_sniffer.py -i eth0 -c 10 -p all
```
Output:
```bash
Time: 2025-05-19 14:21:05
[+] Source IP      : 192.168.0.2
[+] Destination IP : 93.184.216.34
[+] Protocol       : TCP
[+] Source Port    : 51523
[+] Destination Port: 80
[+] Payload        :
GET / HTTP/1.1
Host: example.com
```
## 📄 License
This project is released under the MIT License.

## 🔐 Security & Ethical Use
✅ Only sniff on interfaces you own or have permission to monitor.

❌ Do not use on corporate, public, or private networks without consent.

🧠 Great for network labs, penetration testing training, or OSI model exploration.
