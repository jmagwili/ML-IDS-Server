import os
import time
import pandas as pd
from cols import column_rename_map
import xgboost as xgb
import numpy as np
import shutil
import random

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
model_path = r"C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\ML-IDS-SERVER\xgb_ids_model_v2.json"
source_folder = r'C:\Users\Teano\Documents\DATASETS\Portscan'
destination_folder = r'C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\ML-IDS-SERVER\output'
output_folder = r'C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\ML-IDS-SERVER\output'

# attack_type = "SSH"

def type_switch(attack_type):
    if attack_type in ["Bot", "SSH", "Portscan", "DoS"]:
        return os.path.join('C:\\Users\\Teano\\Documents\\DATASETS', attack_type)
    else:
        raise ValueError(f"Unsupported attack type: {attack_type}")
    
# type_switch(attack_type)

# will be use in the server soon
def simulate_file_generation(source_folder, output_folder):
    try:
        files = [f for f in os.listdir(source_folder) if f.endswith('.csv')]
        if not files:
            print("[!] No CSV files found in source folder to generate.")
            return

        file_to_copy = random.choice(files)
        src_path = os.path.join(source_folder, file_to_copy)
        dest_path = os.path.join(output_folder, f"copy_{int(time.time())}_{file_to_copy}")
        shutil.copy(src_path, dest_path)
        print(f"[+] Simulated file generated: {dest_path}")
    except Exception as e:
        print(f"[!] Error simulating file generation: {e}")

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

    while True:
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

        #simulate_file_generation(source_folder, output_folder) ## GENERATE FILE WHEN SERVER TRIGGERED

        time.sleep(poll_interval)


# Example usage
monitor_and_predict(output_folder)
generate_file = r'C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\Network-Intrusion-Detection-System-with-ML\test\BOTNET ATTACK'
