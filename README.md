# 🔐 Hybrid Intrusion Detection System (IDS)

A Real time based Intrusion Detection System combining **signature-based** and **anomaly-based** detection to monitor network traffic in real-time.

## 🚀 Features

- Real-time packet capturing using **Scapy**
- Traffic analysis and feature extraction
- Hybrid detection engine (signature + anomaly-based using Isolation Forest)
- Structured alert logging with timestamps, confidence scores, and threat metadata
- Easily extendable with custom rules and notification integrations

## ⚙️ System Components

- **Packet Capture Engine** – Captures TCP/IP packets using Scapy
- **Traffic Analyzer** – Extracts flow-level features like byte rate, packet rate, etc.
- **Detection Engine** – Detects threats using known signatures and machine learning
- **Alert System** – Logs alerts and supports extensible notification mechanisms

## 🧰 Installation

1. Install Python 3.x

2. Install dependencies:

```bash
pip install scapy python-nmap numpy scikit-learn
```

3. **Important**: Install [Npcap](https://nmap.org/npcap/) (required by Scapy to capture packets on Windows)

4. Clone this repository:

```bash
git clone https://github.com/yourusername/hybrid-ids.git
cd hybrid-ids
```

> ⚠️ Run the script with administrator/root privileges for Scapy to capture packets properly.

## 💻 Usage

To run the IDS:

```bash
sudo python3 main.py
```

> Replace `main.py` with your script file containing the integrated code.

To change the network interface:

```python
ids = IntrusionDetectionSystem(interface="your_interface")
```

To list available interfaces:

```bash
ifconfig    # on Linux/macOS
ipconfig    # on Windows
```

## 📁 Logs

All detected threats are stored in `ids_alerts.log` with:

- ⏰ Timestamp
- 🔍 Threat type (signature or anomaly)
- 🎯 Source & Destination IP addresses
- ✅ Confidence score

### Example log entry:

```json
{
  "timestamp": "2025-06-13T12:34:56.789",
  "threat_type": "anomaly",
  "source_ip": "192.168.1.5",
  "destination_ip": "93.184.216.34",
  "confidence": 0.92,
  "details": {
    "type": "anomaly",
    "score": -0.76,
    "confidence": 0.92
  }
}
```

## 🧪 Training the Anomaly Detector

To train the anomaly detection model on normal traffic:

```python
detection_engine.train_anomaly_detector(normal_traffic_data)
```

Where `normal_traffic_data` is a NumPy array of feature vectors like:

```python
[packet_size, packet_rate, byte_rate]
```

## 🔄 Extending the IDS

- Add new detection rules in `load_signature_rules()` inside `DetectionEngine`
- Add integrations (email, Slack, SIEM) in `AlertSystem.generate_alert()`
- Expand feature extraction in `TrafficAnalyzer.extract_features()`

## 📚 Requirements

- Python 3.x
- [Npcap](https://nmap.org/npcap/) (on Windows)
- scapy
- python-nmap
- numpy
- scikit-learn


