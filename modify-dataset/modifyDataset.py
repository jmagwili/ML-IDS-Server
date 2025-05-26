import os
import random
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
import ipaddress
import xgboost as xgb
import numpy as np
from cols import column_rename_map


load_dotenv()

INPUT_PATH = os.getenv('INPUT_PATH')
OUTPUT_PATH = os.getenv('OUTPUT_PATH')

model_path = r"C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\ML-IDS-SERVER\xgb_ids_model_v2.json"
class_id_to_label = {
    0: "BENIGN", 1: "Bot", 2: 'DDoS', 3: 'DoS GoldenEye', 4: 'DoS Hulk',
    5: 'DoS Slowhttptest', 6: 'DoS slowloris', 7: 'FTP-Patator', 8: 'Heartbleed',
    9: 'Infiltration', 10: 'PortScan', 11: 'SSH-Patator',
    12: 'Web Attack - Brute Force', 13: 'Web Attack - Sql Injection', 14: 'Web Attack - XSS',
}

if not INPUT_PATH or not OUTPUT_PATH:
    raise EnvironmentError("INPUT_PATH or OUTPUT_PATH environment variable not set.")

def type_switch(attack_type):
    if attack_type in ["Bot", "SSH", "Portscan", "DoS", "FTP"]:
        return os.path.join('C:\\Users\\Teano\\Documents\\DATASETS', attack_type)
    else:
        raise ValueError(f"Unsupported attack type: {attack_type}")

def retype(attack_type):
    mapping = {
        "FTP": "FTP-Patator",
        "SSH": "SSH-Patator",
        "DoS": "DoS slowloris",
        "Portscan": "PortScan"
    }
    return mapping.get(attack_type, attack_type)

def random_public_ip():
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        ip_obj = ipaddress.ip_address(ip)
        if not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        ):
            return ip

def generate_file(source_folder, output_folder, attack_type, src_ip, dst_ip):
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        source_folder = type_switch(attack_type)
        files = [f for f in os.listdir(source_folder) if f.endswith('.csv')]
        if not files:
            print("[!] No CSV files found in source folder to generate.")
            return

        file_to_copy = random.choice(files)
        src_path = os.path.join(source_folder, file_to_copy)

        df = pd.read_csv(src_path)

        # Update all timestamps
        df['Timestamp'] = current_time

        actual_label = retype(attack_type)
        mask = df['Label'] == actual_label

        if attack_type == "Bot":
            # Only update Timestamp and Dst IP for 'Bot' attack
            df['Timestamp'] = current_time

            # Generate a list of random Src IPs
            random_src_ips = [random_public_ip() for _ in range(mask.sum())]

            # Update Dst IP and assign random Src IP for each row with 'Bot' label
            df.loc[mask, 'Src IP'] = random_src_ips
            df.loc[mask, 'Dst IP'] = dst_ip

            df.loc[mask, 'Flow ID'] = df.loc[mask].apply(
                lambda row: f"{row['Src IP']}-{dst_ip}-{row['Src Port']}-{row['Dst Port']}-{row['Protocol']}", axis=1
            )
        else:
            # Update Timestamp
            df['Timestamp'] = current_time
            # Update IPs and Flow ID for matched label rows
            df.loc[mask, 'Src IP'] = src_ip
            df.loc[mask, 'Dst IP'] = dst_ip
            df.loc[mask, 'Flow ID'] = df.loc[mask].apply(
                lambda row: f"{src_ip}-{dst_ip}-{row['Src Port']}-{row['Dst Port']}-{row['Protocol']}", axis=1
            )

        # --- Now predict anomalies on the generated file ---
        print(f"[+] Running prediction on generated file...")
        # Load model (same as your prediction function)
        model = xgb.Booster()
        model.load_model(model_path)

        # Prepare DataFrame for prediction
        df_pred = df.rename(columns=column_rename_map)
        df_original = df_pred.copy()

        non_feature_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label', 'Source Port', 'Destination Port']
        df_pred = df_pred.drop(columns=[col for col in non_feature_cols if col in df_pred.columns], errors='ignore')

        # Compute additional features as in your predict_anomalies
        if 'Flow Duration' in df_pred.columns:
            if 'Total Fwd Packets' in df_pred.columns and 'Total Backward Packets' in df_pred.columns:
                total_packets = df_pred['Total Fwd Packets'] + df_pred['Total Backward Packets']
                df_pred['Flow Packets/s'] = total_packets / (df_pred['Flow Duration'] / 1e6 + 1e-6)
                df_pred['Fwd Packets/s'] = df_pred['Total Fwd Packets'] / (df_pred['Flow Duration'] / 1e6 + 1e-6)
            if 'Fwd Packets Length Total' in df_pred.columns and 'Bwd Packets Length Total' in df_pred.columns:
                total_bytes = df_pred['Fwd Packets Length Total'] + df_pred['Bwd Packets Length Total']
                df_pred['Flow Bytes/s'] = total_bytes / (df_pred['Flow Duration'] / 1e6 + 1e-6)

        expected_model_features = model.feature_names

        for feature in set(expected_model_features) - set(df_pred.columns):
            df_pred[feature] = 0.0

        df_pred = df_pred[expected_model_features]
        dmatrix = xgb.DMatrix(df_pred, feature_names=expected_model_features)
        pred_probs = model.predict(dmatrix)

        predicted_indices = np.argmax(pred_probs, axis=1)
        predicted_classes = [class_id_to_label[idx] for idx in predicted_indices]
        confidence_scores = np.max(pred_probs, axis=1)

        df_original['Prediction'] = predicted_classes
        df_original['Confidence'] = confidence_scores

        # Find suspicious rows (your pattern)
        suspicious_mask = df_original['Prediction'].str.contains('DoS|Bot|PortScan|SSH|FTP', na=False)
        suspicious = df_original[suspicious_mask]

        if not suspicious.empty:
            print("[!] Suspicious flows detected. Modifying their Src IP and Dst IP...")

            if attack_type != "Bot":
                # For attacks other than Bot, keep the fixed src_ip and dst_ip, no randomization
                df.loc[suspicious_mask, 'Src IP'] = src_ip
                df.loc[suspicious_mask, 'Dst IP'] = dst_ip

                df.loc[suspicious_mask, 'Flow ID'] = df.loc[suspicious_mask].apply(
                    lambda row: f"{src_ip}-{dst_ip}-{row['Src Port']}-{row['Dst Port']}-{row['Protocol']}", axis=1
                )
            else:

                random_src_ips = [random_public_ip() for _ in range(suspicious.shape[0])]
                df.loc[suspicious_mask, 'Src IP'] = random_src_ips
                df.loc[suspicious_mask, 'Dst IP'] = dst_ip

                # For Bot attack type, keep the randomized Src IPs, but update Flow ID with those IPs and dst_ip
                df.loc[suspicious_mask, 'Flow ID'] = df.loc[suspicious_mask].apply(
                    lambda row: f"{row['Src IP']}-{dst_ip}-{row['Src Port']}-{row['Dst Port']}-{row['Protocol']}", axis=1
                )


            final_path = os.path.join(output_folder, f"traffic_{timestamp_str}_enhanced.csv")
            df.to_csv(final_path, index=False)
            print(f"[+] Suspicious rows updated and saved to: {final_path}")

        else:
            print("[+] No suspicious flows detected after prediction.")

            # Save the modified file here if no suspicious flows detected
            final_path = os.path.join(output_folder, f"traffic_{timestamp_str}_enhanced.csv")
            df.to_csv(final_path, index=False)
            print(f"[+] Modified file saved to: {final_path}")

    except Exception as e:
        print(f"[!] Error simulating file generation: {e}")

if __name__ == "__main__":
    generate_file(
        source_folder=INPUT_PATH,
        output_folder=OUTPUT_PATH,
        attack_type="FTP",
        src_ip="192.168.254.102",
        dst_ip="192.168.56.1"
    )
    print("File generation complete.")
