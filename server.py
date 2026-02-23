import joblib
import numpy as np
import pandas as pd

model = joblib.load("final_model_1.pkl")

selected_columns = [
    'Protocol', 'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
    'Packet Length Mean', 'Flow IAT Mean', 'Flow IAT Std',
    'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count'
]

def predict_flow(flow_features):
    prediction = model.predict(flow_features)
    score = model.decision_function(flow_features)
    return prediction, score

def print_result(label, sample):
    prediction, score = predict_flow(sample)
    status = "ANOMALY" if prediction[0] == -1 else "NORMAL"
    print(f"{label}")
    print(f"  Prediction:    {status}")
    print(f"  Anomaly score: {score[0]:.4f}  (negative = anomalous)")
    print()

# ── Test 1: Known attack sample (DDoS median values) ──
sample_attack = pd.DataFrame(
    [[6, 73715610, 138.37, 0.179, 850.71, 6025412, 18900000, 0, 1, 0]],
    columns=selected_columns
)

# ── Test 2: Known benign sample (typical normal traffic) ──
sample_benign = pd.DataFrame(
    [[6, 52000, 4207.0, 66.0, 66.0, 21000, 13437, 0, 0, 0]],
    columns=selected_columns
)

# ── Test 3: Extreme DDoS (high packet rate, tiny packets) ──
sample_ddos = pd.DataFrame(
    [[6, 100000, 9000000, 150000, 6, 2, 1, 5000, 0, 100]],
    columns=selected_columns
)

# ── Test 4: Custom sample (edit these values yourself) ──
sample_custom = pd.DataFrame(
    [[6, 2000000, 1500000, 25000, 60, 50, 20, 500, 5, 0]],
    columns=selected_columns
)

print("=" * 45)
print("   ISOLATION FOREST — PREDICTION TESTS")
print("=" * 45)
print()
print_result("Test 1: DDoS median values",  sample_attack)
print_result("Test 2: Normal benign traffic", sample_benign)
print_result("Test 3: Extreme DDoS traffic",  sample_ddos)
print_result("Test 4: Custom sample",         sample_custom)
