import os
import pandas as pd
import xgboost as xgb
import numpy as np
from cols import column_rename_map

# CONSTANTS
model_path = r"C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\ML-IDS-SERVER\xgb_ids_model_v2.json"
output_folder = r'C:\Users\Teano\Documents\IDS-ML-TESTING\Signature Based Intrusion Detection Sysytem\ML-IDS\ML-IDS-SERVER\output'

# Attack class mapping
class_id_to_label = {
    0: "BENIGN", 1: "Bot", 2: 'DDoS', 3: 'DoS GoldenEye', 4: 'DoS Hulk',
    5: 'DoS Slowhttptest', 6: 'DoS slowloris', 7: 'FTP-Patator', 8: 'Heartbleed',
    9: 'Infiltration', 10: 'PortScan', 11: 'SSH-Patator',
    12: 'Web Attack - Brute Force', 13: 'Web Attack - Sql Injection', 14: 'Web Attack - XSS',
}

def predict_anomalies(csv_path):
    try:
        print(f"\n[+] Predicting on file: {os.path.basename(csv_path)}")
        try:
            df = pd.read_csv(csv_path, encoding='utf-8')
        except UnicodeDecodeError:
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

        for feature in set(expected_model_features) - set(df.columns):
            df[feature] = 0.0

        df = df[expected_model_features]
        dmatrix = xgb.DMatrix(df, feature_names=expected_model_features)
        pred_probs = model.predict(dmatrix)

        predicted_indices = np.argmax(pred_probs, axis=1)
        predicted_classes = [class_id_to_label[idx] for idx in predicted_indices]
        confidence_scores = np.max(pred_probs, axis=1)

        df_original['Prediction'] = predicted_classes
        df_original['Confidence'] = confidence_scores

        print("[+] Prediction Summary:")
        print(df_original['Prediction'].value_counts())

        suspicious = df_original[df_original['Prediction'].str.contains('DoS|Bot', na=False)]
        if not suspicious.empty:
            print("[!] Suspicious flows detected:")
            print(suspicious[['Source IP', 'Destination IP', 'Prediction', 'Confidence']].to_string())

    except Exception as e:
        print(f"[!] Error during prediction: {e}")

def predict_all_in_output_folder():
    csv_files = [f for f in os.listdir(output_folder) if f.lower().endswith('.csv')]
    if not csv_files:
        print("[-] No CSV files found in the output folder.")
        return

    for csv_file in sorted(csv_files):
        full_path = os.path.join(output_folder, csv_file)
        predict_anomalies(full_path)

if __name__ == "__main__":
    predict_all_in_output_folder()
