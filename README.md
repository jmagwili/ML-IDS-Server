# Network Intrusion Detection System (IDS)

A real-time network intrusion detection system that uses machine learning to detect various types of network attacks and anomalies.

## Features

- Real-time network traffic capture and analysis
- Machine learning-based attack detection using XGBoost
- Support for multiple attack types:
  - Bot attacks
  - DDoS attacks
  - DoS attacks (GoldenEye, Hulk, SlowHTTPTest, Slowloris)
  - FTP-Patator
  - Heartbleed
  - Infiltration
  - Port Scanning
  - SSH-Patator
  - Web Attacks (Brute Force, SQL Injection, XSS)
- Confidence scoring for each detection
- Detailed flow analysis and reporting

## Prerequisites

- Python 3.7+
- Windows OS (for network interface compatibility)
- Administrator privileges
- Wireshark (for packet capture)
- CICFlowMeter 4.0

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd IDS-Project
```

2. Install CICFlowMeter 4.0:
   - Download from [CICFlowMeter GitHub](https://github.com/ahlashkari/CICFlowMeter)
   - Extract to `{Your project path}\CICFlowMeter-4.0`

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Configure the constants in `ids.py`:
```python
INTERFACE = "Ethernet 3"  # Change to your network interface
TARGET_IP = "192.168.18.56"  # Change to your target IP
CAPTURE_DURATION = 60  # seconds
OUTPUT_PATH = r"D:\IDS-Project\output"
CFM_PATH = r"D:\IDS-Project\CICFlowMeter-4.0\bin\cfm.bat"
INPUT_PATH = r"D:\IDS-Project\pcap_store"
```

## Usage

1. Run the script with administrator privileges:
```bash
python ids.py
```

2. The script will:
   - Capture network traffic for the specified duration
   - Process the captured traffic using CICFlowMeter
   - Analyze the flows using the trained XGBoost model
   - Output detection results to CSV files

## Output

The system generates two main outputs:
1. A PCAP file containing the captured network traffic
2. A CSV file containing the analysis results, including:
   - Flow information
   - Predicted attack type
   - Confidence scores
   - Additional flow metrics

## Project Structure

```
IDS-Project/
├── ids.py                 # Main IDS script
├── cols.py               # Column mapping definitions
├── training_features.json # Expected feature list
├── xgb_ids_model_v3.json # Trained XGBoost model
├── requirements.txt      # Python dependencies
├── output/               # Output directory for analysis results
├── pcap_store/          # Directory for captured PCAP files
└── CICFlowMeter-4.0/    # CICFlowMeter installation
```

## Dependencies

The project uses the following main Python packages (see requirements.txt for complete list):
- pyshark: Network packet capture and analysis
- pandas: Data manipulation and analysis
- numpy: Numerical operations
- xgboost: Machine learning model
- scapy: Packet manipulation

## Model Training

The system uses a pre-trained XGBoost model (`xgb_ids_model_v3.json`). The model was trained on the CICIDS2017 dataset and can detect multiple types of network attacks.

