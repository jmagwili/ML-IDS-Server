import os
import time
import pandas as pd
from cols import column_rename_map
import xgboost as xgb
import numpy as np
import shutil
import random
import threading
import subprocess
from scapy.all import *

# Class mapping (as you have it)
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




# CONSTANTS
model_path = r"C:\Users\User\Documents\personal-projects\ML-IDS-Server\xgb_ids_model_v2.json"
source_folder = r'C:\Users\User\Documents\personal-projects\ML-IDS-Server\datasets'
destination_folder = r'C:\Users\User\Documents\personal-projects\ML-IDS-Server\output'
output_folder = r'C:\Users\User\Documents\personal-projects\ML-IDS-Server\output'
INPUT_PATH = r"C:\Users\User\Documents\personal-projects\ML-IDS-Server\pcap_store"
CFM_PATH = r"C:\Users\User\Documents\personal-projects\ML-IDS-Server\CICFlowMeter-4.0\bin\cfm.bat"
INTERFACE = "Wi-Fi"  # Change to your network interface
TARGET_IP = " 192.168.56.1"  # Change to your target IP
CAPTURE_DURATION = 60  # seconds

stop_event = threading.Event()


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


def predict_anomalies(csv_path, model_path=model_path):
    try:
        print(f"[+] Predicting on file: {os.path.basename(csv_path)}")
        try:
            df = pd.read_csv(csv_path, encoding='utf-8')
        except UnicodeDecodeError:
            print("[!] UTF-8 decode failed, trying 'latin1' encoding...")
            df = pd.read_csv(csv_path, encoding='latin1')

        df = df.rename(columns=column_rename_map)
        df_original = df.copy()

        non_feature_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label', 'Source Port', 'Destination Port']
        df = df.drop(columns=[col for col in non_feature_cols if col in df.columns], errors='ignore')

        if 'Flow Duration' in df.columns:
            if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
                total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
                df['Flow Packets/s'] = total_packets / (df['Flow Duration'] / 1e6 + 1e-6)
                df['Fwd Packets/s'] = df['Total Fwd Packets'] / (df['Flow Duration'] / 1e6 + 1e-6)
            if 'Fwd Packets Length Total' in df.columns and 'Bwd Packets Length Total' in df.columns:
                total_bytes = df['Fwd Packets Length Total'] + df['Bwd Packets Length Total']
                df['Flow Bytes/s'] = total_bytes / (df['Flow Duration'] / 1e6 + 1e-6)

        model = xgb.Booster()
        model.load_model(model_path)
        expected_model_features = model.feature_names

        missing_features = set(expected_model_features) - set(df.columns)
        for feature in missing_features:
            df[feature] = 0.0

        df = df[expected_model_features]
        dmatrix = xgb.DMatrix(df, feature_names=expected_model_features)
        pred_probs = model.predict(dmatrix)

        predicted_indices = np.argmax(pred_probs, axis=1)
        predicted_classes = [class_id_to_label[idx] for idx in predicted_indices]
        confidence_scores = np.max(pred_probs, axis=1)

        df_original['Prediction'] = predicted_classes
        df_original['Confidence'] = confidence_scores

        print("\n[+] Prediction Summary:")
        print(df_original['Prediction'].value_counts())

        suspicious = df_original[df_original['Prediction'].str.contains('DoS|DDoS', na=False)]
        if not suspicious.empty:
            print("\n[!] Suspicious flows detected:")
            print(suspicious[['Source IP', 'Destination IP', 'Prediction', 'Confidence']].to_string())

        return df_original

    except Exception as e:
        print(f"[!] Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        return None


def monitor_and_predict(folder_path, poll_interval=5):
    processed_files = set()
    print(f"Monitoring folder: {folder_path}\n")

    while not stop_event.is_set():
        files = [os.path.join(folder_path, f) for f in os.listdir(folder_path)
                 if os.path.isfile(os.path.join(folder_path, f)) and f.lower().endswith('.csv')]

        new_files = [f for f in files if f not in processed_files]
        new_files.sort(key=lambda x: os.path.getmtime(x))

        if new_files:
            print("\n=== New Files Detected ===")
            for i, file_path in enumerate(new_files, 1):
                print(f"\n[{i}] Processing: {os.path.basename(file_path)}")
                processed_files.add(file_path)
                predict_anomalies(file_path)
        else:
            print(f"[{time.ctime()}] No new files...")

        time.sleep(poll_interval)

def generate_pcap_csv():
    while not stop_event.is_set():

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
            if not run_cfm(CFM_PATH, pcap_to_process, output_folder):
                print("[!] CICFlowMeter processing failed")
                return
            
            # Find the generated CSV (more robust handling)
            base_name = os.path.basename(pcap_to_process).rsplit('.', 1)[0]
            csv_files = [
                f for f in os.listdir(output_folder)
                if f.startswith(base_name) and f.lower().endswith(".csv")
            ]
            
            if not csv_files:
                print(f"[!] No CSV found for {base_name} in {output_folder}")
                print(f"Available files: {os.listdir(output_folder)}")
                return
                
        except Exception as e:
            print(f"[!] Processing error: {e}")
            import traceback
            traceback.print_exc()

# Example usage
# monitor_and_predict(output_folder)
def main():
    try:
        t1 = threading.Thread(target=monitor_and_predict, args=(output_folder,))
        t2 = threading.Thread(target=generate_pcap_csv)
        t1.start()
        t2.start()

        # Keep main thread alive and responsive to Ctrl+C
        while t1.is_alive() or t2.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C pressed. Exiting gracefully...")
        stop_event.set()
        t1.join()
        t2.join()
        print("[+] Exited cleanly.")

if __name__ == "__main__":
    main()

# generate_file = r'C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\Network-Intrusion-Detection-System-with-ML\test\BOTNET ATTACK'
