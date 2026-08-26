# TrackNET: Real-Time AI Network Intrusion Engine 🛡️

**TrackNET** is a high-performance Network Intrusion Detection System (NIDS) engineered in C++ that captures live network traffic and evaluates it against a Machine Learning model in real-time. 

This repository is divided into two core domains: the **C++ Packet Capture & Inference Engine** and the **Python Machine Learning Model**.

---

## ⚙️ Core C++ Architecture (Engine & Interface)
**Lead Developer:** Farhan Khan

The TrackNET engine is built for microsecond-latency processing, designed to sit directly on the network interface and extract complex flow features without interrupting the host system.

### Key Features
*   **Bare-Metal Packet Sniffing:** Utilizes the Npcap library to intercept live Ethernet, IPv4, and TCP traffic at the network layer.
*   **Bidirectional Flow Tracking:** Implements a custom, highly optimized C++ Hash Map (`std::unordered_map`) to track stateful network flows in both directions (Client-to-Server and Server-to-Client).
*   **Real-Time Feature Extraction:** Dynamically calculates advanced metrics on the fly, including:
    *   TCP Handshake Timestamps (SYN, SYN-ACK, ACK)
    *   Round Trip Times (RTT)
    *   Packet sizes, TTL tracking, and payload payload bitrates.
*   **Zero-Latency ML Integration:** Integrates the Microsoft **ONNX Runtime (C++ API)** to deserialize and execute a Scikit-Learn Random Forest model directly against live traffic arrays in memory.
*   **Actionable Threat Intelligence:** Translates raw integer IP addresses into human-readable strings via `inet_ntoa` and outputs immediate, categorized threat alerts (e.g., Exploits, DoS, Shellcode) directly to the terminal.

---

## 🧠 Machine Learning & Data Science (Detector)
**Lead Developer:** Shuvam Chatterjee



---

## 🚀 Installation & Deployment

### Option 1: The Quick Installer (Recommended)
You do not need to compile the code to run TrackNET. 
1. Navigate to the **[Releases](../../releases)** tab on this repository.
2. Download `TrackNET_Setup.exe`.
3. Run the installer (it will automatically prompt you to install the required **Npcap** packet capture driver).
4. Launch TrackNET from your desktop shortcut!

### Option 2: Build from Source (For Developers)
If you want to compile the C++ engine yourself:

**Prerequisites:**
*   [CMake](https://cmake.org/) (3.10+)
*   Visual Studio (MSVC Compiler for x64)
*   Npcap SDK
*   ONNX Runtime C++ API

**Build Steps:**
```bash
# Clone the repository
git clone [https://github.com/ShuvamLabs/network-anomaly-detector.git](https://github.com/ShuvamLabs/network-anomaly-detector.git)
cd network-anomaly-detector

# Create a build directory
mkdir build
cd build

# Configure and compile using CMake
cmake ..
cmake --build . --config Release
```

## 💻 Usage
Run the engine from your terminal with administrator privileges (required for raw socket access). The tool will list your available network interfaces.

DOS
.\capturer.exe

1. \Device\NPF_{...} (Intel(R) Gigabit Network Connection)
2. \Device\NPF_Loopback (Adapter for loopback traffic capture)
Enter the interface number to sniff (1-2): 1

[*] Listening for traffic...
[+] ONNX Model loaded successfully!


## 👥 Credits & Authors

*   **Shuvam Chatterjee** - *Data Science, Model Training, & Feature Engineering* 
    *   [GitHub](https://github.com/ShuvamLabs) | [LinkedIn](https://www.linkedin.com/in/shuvam-chatterjee-74598b258/)

*   **Farhan Khan** - *C++ Systems Engineering, ONNX Integration, & Deployment* 
    *   [GitHub](https://github.com/Khanfuze) | [LinkedIn](https://www.linkedin.com/in/farhan-khan-aa82aa399/)

**License:** This project is licensed under the MIT License - see the `LICENSE` file for details.
