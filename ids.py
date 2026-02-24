import joblib
import numpy as np
import requests
import time
from datetime import datetime
import feature_extraction


LAPTOP_URL = ""


model = joblib.load("final_model_2.pkl")
print("Model loaded!\n\n")

def main():
    while True:
        flows = feature_extraction.extract_features()

        for meta, features in flows:
            prediction = model.predict([features])[0]

            if prediction == -1:
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
                    "label": "ANOMALY"
                }

                print(f" ANOMALY !: \n{meta['src_ip']} → {meta['dst_ip']}\n")

                try:
                    requests.post(LAPTOP_URL, json=alert, timeout=3)
                    
                except requests.exceptions.RequestException as e:
                    print(f"Failed to send alert: {e}")

            else:
                print(f"Normal Traffic")

        time.sleep(1)

if __name__ == "__main__":
    main()