import joblib
import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"


# Load models
network_model = joblib.load(
    MODEL_DIR / "network_attack_model.pkl"
)

bot_specialist = joblib.load(
    MODEL_DIR / "bot_specialist_model.pkl"
)

network_imputer = joblib.load(
    MODEL_DIR / "network_imputer.pkl"
)

label_encoder = joblib.load(
    MODEL_DIR / "network_label_encoder.pkl"
)


# EXACT 65 features used during training
NETWORK_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


def detect_network_attack(flow_data: dict):

    # Keep only trained features in exact order
    row = {
        feature: flow_data.get(feature)
        for feature in NETWORK_FEATURES
    }

    X = pd.DataFrame([row], columns=NETWORK_FEATURES)

    # Convert values to numeric
    X = X.apply(pd.to_numeric, errors="coerce")

    # Apply the SAME imputer used during training
    X_imputed = network_imputer.transform(X)

    # Main multiclass model
    probabilities = network_model.predict_proba(X_imputed)[0]

    predicted_index = probabilities.argmax()

    predicted_attack = label_encoder.inverse_transform(
        [predicted_index]
    )[0]

    model_score = float(probabilities[predicted_index])

    # Bot specialist
    bot_score = float(
        bot_specialist.predict_proba(X_imputed)[0][1]
    )

    # Validate Bot predictions using specialist
    if predicted_attack == "Bot" and bot_score < 0.90:

        non_bot_indices = [
            i for i, label in enumerate(label_encoder.classes_)
            if label != "Bot"
        ]

        best_non_bot_index = max(
            non_bot_indices,
            key=lambda i: probabilities[i]
        )

        predicted_attack = label_encoder.inverse_transform(
            [best_non_bot_index]
        )[0]

        model_score = float(
            probabilities[best_non_bot_index]
        )

    return {
        "attack_type": predicted_attack,
        "model_score": round(model_score, 4),
        "bot_specialist_score": round(bot_score, 4),
        "is_attack": predicted_attack != "BENIGN",
    }