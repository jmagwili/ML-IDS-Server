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
import os
import pandas as pd
 # Import your existing function
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cols import column_rename_map
from ids import class_id_to_label
import os
import json
import pickle

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_PATH = r"D:\IDS-Project\training_features.json"
# Configuration
TEST_CSV = r"D:\IDS-Project\test_assets\ten_malicious_rows.csv"  
OUTPUT_CSV = r"D:\IDS-Project\test_assets\test_output.csv"  

def predict_anomalies(csv_path, model_path=r"D:\IDS-Project\xgb_ids_model_v2.json"):
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

def analyze_csv(csv_path):
    """Reuse your existing predict_anomalies function"""
    print(f"\n[+] Analyzing {csv_path}")
    
    # Call your existing function
    results = predict_anomalies(csv_path)
    
    if results is not None:
        # Save full results
        results.to_csv(OUTPUT_CSV, index=False)
        print(f"[+] Saved results to {OUTPUT_CSV}")
        
        # Print detection summary
        print("\n=== Detection Summary ===")
        print(results['Prediction'].value_counts())

if __name__ == "__main__":
    analyze_csv(TEST_CSV)