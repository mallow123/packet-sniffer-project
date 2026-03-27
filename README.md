# 🧠 TCP/UDP Packet Sniffer with GUI & Basic Intrusion Detection

A powerful, lightweight, and user-friendly **network packet sniffer** built using Python.  
This project captures, analyzes, and visualizes network traffic in real time with a clean GUI and basic threat detection features.

---

## 🚀 Features

- 📡 Capture live network packets (TCP/UDP/ALL)
- 🎛️ Select network interface dynamically
- 🖥️ Clean GUI using Tkinter
- 📊 Real-time packet statistics & live graph
- ⚡ Speed monitoring (KB/s)
- 🚨 Suspicious activity detection:
  - Port scanning detection
  - High traffic (DoS-like behavior)
- 💾 Export captured packets to CSV
- 🔐 Login system using SQLite
- 🎨 Styled UI (Treeview + Dashboard)

---

## 🛠️ Tech Stack

- Python 3
- Scapy
- Tkinter
- Matplotlib
- SQLite3

---

## 📁 Project Structure
```
packet-sniffer-project/
│
├── dashboard.py # Main GUI + dashboard
├── sniffer.py # Packet capture logic (Scapy)
├── detection.py # Threat detection logic
├── database.py # SQLite login system
├── users.db # User database
├── requirements.txt # Dependencies
├── README.md # Project documentation
│
├── exports/ # CSV exports folder
│ └── packets.csv
│
└── assets/ # UI assets (optional)
```
## ⚙️ Installation (Ubuntu / Linux)

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/packet-sniffer-project.git
cd packet-sniffer-project
```
### 2️⃣ Install Python & Required Packages
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv python3-tk -y
```
### 3️⃣ Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```
### 4️⃣ Install Dependencies
```bash
pip install scapy matplotlib
```
### ▶️ Running the Project
```bash
sudo venv/bin/python dashboard.py
```
## 🧪 How It Works

### 🔍 Packet Capture
- Uses **Scapy** to sniff packets from selected interface
- Supports filtering:
  - TCP
  - UDP
  - ALL

---

### 📊 Real-Time Monitoring
- Displays packets in GUI table:
  - Source IP
  - Destination IP
  - Protocol
  - Source Port
  - Destination Port
- Live counters:
  - Total packets
  - TCP packets
  - UDP packets
- Speed calculation:
  - KB/s based on packet size

---

### 🚨 Threat Detection Logic
- Flags suspicious ports:
  ```
  21, 22, 23, 3389, 4444, 8080
  ```
  - Tracks packet count per IP:
- If > 50 packets → Possible **Port Scan / DoS Attack**

---

### 📈 Visualization
- Real-time graph using **Matplotlib**
- Displays packets captured over time

---

### 💾 Data Export
- Captured packets saved as CSV:
  ```
  exports/packets.csv
  ```
  
---

## 🧑‍💻 Login System

- SQLite-based authentication
- Database file:
  ```
  users.db
  ```
  
---

## 🧩 Common Issues & Fixes

### ❌ externally-managed-environment error
✔️ Use virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
❌ Tkinter not working
```
sudo apt install python3-tk -y
```
❌ Permission denied (sniffing)
```
sudo venv/bin/python dashboard.py
```
❌ Matplotlib animation warning
```
self.ani = FuncAnimation(...)
```

---
## 🎯 Project Objectives
- Understand network packet flow
- Implement real-time monitoring systems
- Build GUI-based cybersecurity tools
- Detect basic network attacks

## 🚀 Future Enhancements
- 🔍 Deep Packet Inspection (payload analysis)
- 🤖 AI-based anomaly detection
- 📩 Alert system (email/notifications)
- 🗄️ Database logging (instead of CSV)
- 🌐 Multi-device monitoring

##  📌 Why This Project?
This project demonstrates:

- Networking fundamentals
- Cybersecurity basics
- GUI development
- Real-time data processing

It acts as a lightweight alternative to tools like Wireshark, designed for learning and customization.

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

## ⭐ Show Some Love
If you liked this project:

- ⭐ Star the repo
- 🍴 Fork it
- 🚀 Build on top of it
