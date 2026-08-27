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
    *   Statistical Normalization & Encoding: Implements an in-memory StandardScaler pipeline (subtracting trained feature means and dividing by standard deviations) alongside categorical one-hot encoding for protocols,           states, and services to match the exact training distribution of the model.
*   **Zero-Latency ML Integration:** Integrates the Microsoft **ONNX Runtime (C++ API)** to deserialize and execute a Scikit-Learn Random Forest model directly against live traffic arrays in memory.
*   **Actionable Threat Intelligence:** Translates raw integer IP addresses into human-readable strings via `inet_ntoa` and outputs immediate, categorized threat alerts (e.g., Exploits, DoS, Shellcode) directly to the terminal.

---

## 🧠 Machine Learning & Data Science (Detector)
**Lead Developer:** Shuvam Chatterjee

The Detector module implements the full ML pipeline for anomaly detection. It covers **data preparation, model training, evaluation, and deployment**.

---

### 🔬 ML Workflow

#### 1. Data Collection & Cleaning
- Merge multiple traffic datasets.  
- Remove duplicates, handle missing values, normalize features.  
- Save cleaned dataset for reproducibility.  

#### 2. Feature Engineering
- Extract flow-level features:
  - TCP handshake timings (SYN, SYN-ACK, ACK)  
  - RTT distributions  
  - Packet size statistics  
  - TTL variance  
  - Payload bitrate ratios  
- Store processed features in `processed-data/`.

#### 3. Model Selection & Training
- Compare classifiers (Random Forest, Logistic Regression).  
- Random Forest chosen for best balance of accuracy and speed.  
- Train on labeled datasets (Normal vs. DoS, Exploit, Shellcode).  
- Evaluate with metrics: **accuracy, precision, recall, F1-score**.

#### 4. Model Export
- Final Random Forest model exported to **ONNX format**.  
- Stored in `models/` for deployment.

#### 5. Real-Time Inference
- ONNX Runtime loads the model in the C++ engine.  
- Feature vectors from live traffic passed directly to the model.  
- Predictions generated inline with packet capture (**microsecond latency**).  
- Output categories: *Normal*, *DoS*, *Exploit*, *Shellcode*.



---

## 🚀 Installation & Deployment

### Option 1: The Quick Installer (Recommended)
You do not need to compile the code to run TrackNET. 
1. Navigate to the **[Releases](../../releases)** tab on this repository.
2. Download `TrackNET_Setup.zip`.
3. Extract the zip file to get `TrackNET_Setup.exe`.
4. Run the installer (it will automatically prompt you to install the required **Npcap** packet capture driver).
5. Launch TrackNET from your desktop shortcut!

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
