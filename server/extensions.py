# extensions.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import shutil
import random
import os
import time
import ipaddress
from datetime import datetime
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

INPUT_PATH = os.getenv('INPUT_PATH')
OUTPUT_PATH = os.getenv('OUTPUT_PATH')

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)


def type_switch(attack_type):
    if attack_type in ["Bot", "SSH", "Portscan", "DoS", "FTP"]:
        return os.path.join(INPUT_PATH, attack_type)
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

        dest_path = os.path.join(output_folder, f"traffic_{timestamp_str}_enhanced.pcap_Flow.csv")
        df.to_csv(dest_path, index=False)
        # print(f"[+] Simulated and modified file saved: {dest_path}")

    except Exception as e:
        print(f"[!] Error simulating file generation: {e}")