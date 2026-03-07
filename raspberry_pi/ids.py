import joblib
import numpy as np
import requests
import time
from datetime import datetime
import feature_extraction

LAPTOP_URL = ""

layer1 = joblib.load("final_model_1.pkl")
layer2 = joblib.load("ml_layer2.pkl")

# ─── Feature Names for Layer 2 ────────────────────────────────────────────────
import pandas as pd
feature_names = [
    'Protocol', 'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
    'Packet Length Mean', 'Flow IAT Mean', 'Flow IAT Std',
    'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count'
]

def main():
    while True:
        flows = feature_extraction.extract_features()

        for meta, features in flows:


            prediction = layer1.predict([features])[0]

            if prediction == -1:

                df = pd.DataFrame([features], columns=feature_names)
                attack_type = layer2.predict(df)[0]

                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": meta["src_ip"],
                    "dst_ip": meta["dst_ip"],
                    "protocol": meta["protocol"],
                    "features": {
                        "Protocol":           float(features[0]),
                        "Flow Duration":      float(features[1]),
                        "Flow Bytes/s":       float(features[2]),
                        "Flow Packets/s":     float(features[3]),
                        "Packet Length Mean": float(features[4]),
                        "Flow IAT Mean":      float(features[5]),
                        "Flow IAT Std":       float(features[6]),
                        "SYN Flag Count":     float(features[7]),
                        "ACK Flag Count":     float(features[8]),
                        "RST Flag Count":     float(features[9]),
                    },
                    "label": attack_type
                }

                print(f"ANOMALY! [{attack_type}]\n")

                try:
                    requests.post(LAPTOP_URL, json=alert, timeout=3)
                except requests.exceptions.RequestException as e:
                    print(f"Failed to send alert: {e}")

            else:
                print(f"Normal Traffic")

        time.sleep(1)

if __name__ == "__main__":
    main()