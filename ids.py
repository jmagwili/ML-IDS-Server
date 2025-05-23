import sys
import ctypes
import os
import subprocess
import threading
import time
from datetime import datetime
import pyshark
import pandas as pd
import numpy as np
import xgboost as xgb
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import random
import string
from collections import Counter
from cols import column_rename_map
import pickle
import json
# CONSTANTS
INTERFACE = "Wi-Fi"  # Change to your network interface
TARGET_IP = " 192.168.56.1"  # Change to your target IP
CAPTURE_DURATION = 60  # seconds
OUTPUT_PATH = r"C:\Users\User\Documents\GitHub\Network-Intrusion-Detection-System-with-ML\output"
CFM_PATH = r"C:\Users\User\Documents\GitHub\Network-Intrusion-Detection-System-with-ML\CICFlowMeter-4.0\bin\cfm.bat"
INPUT_PATH = r"C:\Users\User\Documents\GitHub\Network-Intrusion-Detection-System-with-ML\pcap_store"

# Attack class mapping
class_id_to_label = {
    0: "BENIGN",
    1: "Bot",
    2: 'DDoS',
    3: 'DoS GoldenEye',
    4: 'DoS Hulk',
    5: 'DoS Slowhttptest',
    6: 'DoS slowloris',
    7: 'FTP-Patator',
    8: 'Heartbleed',
    9: 'Infiltration',
    10: 'PortScan',
    11: 'SSH-Patator',
    12: 'Web Attack - Brute Force',
    13: 'Web Attack - Sql Injection',
    14: 'Web Attack - XSS',
}


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def ensure_admin():
    if os.name == 'nt' and not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, None)
        sys.exit()

# Update your capture_pcap() function to use dumpcap.exe
def capture_pcap(interface, duration, output_file):
    try:
        # Correct paths to try (in order)
        possible_paths = [
            r"C:\Program Files\Wireshark\dumpcap.exe",
            r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
            r"C:\Program Files\Wireshark\windump.exe"  # Legacy
        ]
        
        # Find the first valid path
        dumpcap_path = None
        for path in possible_paths:
            if os.path.exists(path):
                dumpcap_path = path
                break
                
        if not dumpcap_path:
            raise FileNotFoundError("Neither dumpcap.exe nor windump.exe found")
            
        cmd = [
            dumpcap_path,
            "-i", interface,
            "-w", output_file,
            "-a", f"duration:{duration}",
            "-s", "0",
            "-q"  # Quiet mode
        ]
        
        print(f"[+] Executing: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, timeout=duration+5)
        return True
        
    except Exception as e:
        print(f"[!] Capture failed: {str(e)}")
        return False

def preprocess_pcap(pcap_path):
    try:
        packets = rdpcap(pcap_path)
        new_packets = []
        for pkt in packets:
            new_packets.append(pkt)
            if TCP in pkt and pkt[TCP].flags == "S":  # SYN packet
                # Add fake SYN-ACK response
                syn_ack = IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(
                    dport=pkt[TCP].sport, 
                    sport=pkt[TCP].dport, 
                    flags="SA", 
                    seq=1000, 
                    ack=pkt[TCP].seq + 1
                )
                new_packets.append(syn_ack)
        
        enhanced_path = pcap_path.replace(".pcap", "_enhanced.pcap")
        wrpcap(enhanced_path, new_packets)
        return enhanced_path  # Make sure to return the path
    
    except Exception as e:
        print(f"[!] Preprocessing failed: {e}")
        return None

def clean_features(df):
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    if 'Flow Duration' in df.columns:
        df['Flow Duration'] = df['Flow Duration'].replace(0, 1)
        df['Flow Duration'] = df['Flow Duration'] / 1e6
    
    if 'Tot Fwd Pkts' in df.columns:
        df['Tot Fwd Pkts'] = np.log1p(df['Tot Fwd Pkts'])
    
    return df

def align_features(df):
    for feature in EXPECTED_FEATURES:
        if feature not in df.columns:
            df[feature] = 0
    return df[EXPECTED_FEATURES]

def run_cfm(cfm_path, input_file, output_folder):
    """Run CICFlowMeter to generate flow features"""
    try:
        print(f"[+] Running CICFlowMeter on {input_file}...")
        original_dir = os.getcwd()
        bin_dir = os.path.dirname(cfm_path)
        os.chdir(bin_dir)

        command = f"cfm.bat {input_file} {output_folder}"
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        stdout, stderr = process.communicate()
        os.chdir(original_dir)

        if process.returncode != 0:
            print(f"[!] CICFlowMeter error:\n{stderr}")
            return False
        print("[+] CICFlowMeter completed successfully")
        return True
    except Exception as e:
        print(f"[!] Error running CICFlowMeter: {e}")
        return False

def predict_anomalies(csv_path, model_path=r"C:\Users\User\Documents\GitHub\Network-Intrusion-Detection-System-with-ML\xgb_ids_model_v2.json"):
    try:
        print(f"[+] Loading data from: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # Debug: Print initial data shape and columns
        print(f"[DEBUG] Initial data shape: {df.shape}")
        print(f"[DEBUG] Sample of actual labels: {df['Label'].unique() if 'Label' in df.columns else 'No Label column'}")
        
        # Apply column renaming first
        df = df.rename(columns=column_rename_map)
        df_original = df.copy()

        # Don't drop non-numeric columns - the model expects Protocol
        # Only drop specific columns that aren't needed
        non_feature_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label', 'Source Port', 'Destination Port']
        df = df.drop(columns=[col for col in non_feature_cols if col in df.columns], errors='ignore')

        # Don't drop columns by index - the model expects all features
        # Comment out the column dropping:
        # columns_to_drop = [0, 14, 15, 36, 67]
        # existing_indices = [i for i in columns_to_drop if i < df.shape[1]]
        # df = df.drop(df.columns[existing_indices], axis=1)

        # Load XGBoost model to get expected features
        print("[+] Loading XGBoost model...")
        model = xgb.Booster()
        model.load_model(model_path)
        expected_model_features = model.feature_names
        print(f"[DEBUG] Model expects {len(expected_model_features)} features")
        print(f"[DEBUG] Model expects: {expected_model_features}")

        # Calculate derived features that are expected
        if 'Flow Duration' in df.columns:
            # Don't convert Flow Duration to seconds - keep as microseconds
            # The model was likely trained with microseconds
            print(f"[DEBUG] Keeping Flow Duration in microseconds")
            
            # Calculate Flow Bytes/s, Flow Packets/s, Fwd Packets/s
            if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
                total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
                df['Flow Packets/s'] = total_packets / (df['Flow Duration'] / 1e6 + 1e-6)
                df['Fwd Packets/s'] = df['Total Fwd Packets'] / (df['Flow Duration'] / 1e6 + 1e-6)
                
            if 'Fwd Packets Length Total' in df.columns and 'Bwd Packets Length Total' in df.columns:
                total_bytes = df['Fwd Packets Length Total'] + df['Bwd Packets Length Total']
                df['Flow Bytes/s'] = total_bytes / (df['Flow Duration'] / 1e6 + 1e-6)

        # Ensure we have all features the model expects
        print(f"[DEBUG] Current features: {len(df.columns)}")
        print(f"[DEBUG] Features we have: {list(df.columns)}")
        
        # Check which features are missing
        missing_features = set(expected_model_features) - set(df.columns)
        if missing_features:
            print(f"[WARNING] Missing features: {missing_features}")
            for feature in missing_features:
                df[feature] = 0.0
                print(f"[WARNING] Added missing feature '{feature}' with default value 0")
        
        # Reorder columns to match model expectations exactly
        df = df[expected_model_features]
        
        print(f"[DEBUG] Final feature count: {len(df.columns)}")
        print(f"[DEBUG] Final features match model: {list(df.columns) == expected_model_features}")

        # No scaler needed - use features directly
        print("[+] Using features without scaling...")
       
        # Create DMatrix with features in exact order expected by model
        dmatrix = xgb.DMatrix(df, feature_names=expected_model_features)
        
        # Get prediction probabilities
        pred_probs = model.predict(dmatrix)
        print("Prediction probabilities shape:", pred_probs.shape)
        print("First few predictions:", pred_probs[:5])
        
        # No label encoder needed - map directly using class_id_to_label
        print("[+] Mapping predictions to class names...")
        
        # Get predicted class indices
        predicted_indices = np.argmax(pred_probs, axis=1)
        
        # Map indices to class names using class_id_to_label
        predicted_classes = [class_id_to_label[idx] for idx in predicted_indices]
        confidence_scores = np.max(pred_probs, axis=1)
        
        # Add predictions to the original dataframe
        df_original['Prediction'] = predicted_classes
        df_original['Confidence'] = confidence_scores
        
        # Debug output - use only available columns
        print("\n[+] Detection Summary:")
        print(df_original['Prediction'].value_counts())
        
        # Highlight suspicious flows - check which columns exist first
        available_columns = [col for col in ['flow_id', 'src_ip', 'dst_ip', 'prediction', 'confidence'] 
                           if col in df_original.columns]
        
        suspicious = df_original[df_original['Prediction'].str.contains('DoS|DDoS', na=False)]
        if not suspicious.empty:
            print("\n[!] Suspicious flows detected:")
            print(suspicious[available_columns].to_string())
        
        # Check accuracy if actual labels exist
        if 'Label' in df_original.columns:
            print(f"\n[DEBUG] Actual labels: {df_original['Label'].value_counts()}")
            print(f"\n[DEBUG] Accuracy: {(df_original['Label'] == df_original['Prediction']).mean():.2%}")
            
            # Per-class analysis
            print(f"\n[DEBUG] Per-sample analysis:")
            for i, (actual, predicted, conf) in enumerate(zip(df_original['Label'], df_original['Prediction'], df_original['Confidence'])):
                print(f"  Sample {i}: Actual={actual}, Predicted={predicted}, Confidence={conf:.3f}")
        
        return df_original

    except Exception as e:
        print(f"[!] Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    ensure_admin()
    os.makedirs(INPUT_PATH, exist_ok=True)
    os.makedirs(OUTPUT_PATH, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_pcap = os.path.join(INPUT_PATH, f"traffic_{timestamp}.pcap")
    
    # Start capture (now using direct blocking capture)
    if not capture_pcap(INTERFACE, CAPTURE_DURATION, output_pcap):
        print("[!] Exiting due to capture failure")
        return
    
    # Verify pcap exists
    if not os.path.exists(output_pcap):
        print("[!] No pcap file created. Exiting.")
        return
    
    # Enhanced processing
    try:
        print("[+] Preprocessing pcap file...")
        enhanced_pcap = preprocess_pcap(output_pcap)
        pcap_to_process = enhanced_pcap if enhanced_pcap else output_pcap
        print(f"[+] Using pcap file: {pcap_to_process}")
        
        # Run CICFlowMeter
        print(f"[+] Generating flow features from {pcap_to_process}...")
        if not run_cfm(CFM_PATH, pcap_to_process, OUTPUT_PATH):
            print("[!] CICFlowMeter processing failed")
            return
        
        # Find the generated CSV (more robust handling)
        base_name = os.path.basename(pcap_to_process).rsplit('.', 1)[0]
        csv_files = [
            f for f in os.listdir(OUTPUT_PATH)
            if f.startswith(base_name) and f.lower().endswith(".csv")
        ]
        
        if not csv_files:
            print(f"[!] No CSV found for {base_name} in {OUTPUT_PATH}")
            print(f"Available files: {os.listdir(OUTPUT_PATH)}")
            return
            
        # csv_path = os.path.join(OUTPUT_PATH, csv_files[0])
        csv_path = os.path.join(OUTPUT_PATH, "test_data.csv")
        print(f"[+] Analyzing flows from: {csv_files[0]}")
        
        print(f"CSV file: {csv_path}")

        result = predict_anomalies(csv_path)
        
        if result is not None:
            output_csv = csv_path.replace(".csv", "_predictions.csv")
            result.to_csv(output_csv, index=False)
            print("\n[+] Detection results saved to:", output_csv)
            
    except Exception as e:
        print(f"[!] Processing error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()