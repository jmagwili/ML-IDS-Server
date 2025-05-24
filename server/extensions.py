# extensions.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import shutil
import random
import os
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)


def type_switch(attack_type):
    if attack_type in ["Bot", "SSH", "Portscan", "DoS"]:
        return os.path.join('C:\\Users\\Teano\\Documents\\DATASETS', attack_type)
    else:
        raise ValueError(f"Unsupported attack type: {attack_type}")

def generate_file(source_folder, output_folder, attack_type):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        source_folder = type_switch(attack_type)  # <-- assign the returned value
        files = [f for f in os.listdir(source_folder) if f.endswith('.csv')]
        if not files:
            print("[!] No CSV files found in source folder to generate.")
            return

        file_to_copy = random.choice(files)
        src_path = os.path.join(source_folder, file_to_copy)
        dest_path = os.path.join(output_folder, f"traffic_{timestamp}_enhanced.pcap_Flow.csv")
        shutil.copy(src_path, dest_path)
        print(f"[+] Simulated file generated: {dest_path}")
    except Exception as e:
        print(f"[!] Error simulating file generation: {e}")