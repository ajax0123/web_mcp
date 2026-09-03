import joblib
import pandas as pd
from pathlib import Path


# ================================================================
# PATHS
# ================================================================

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"


# ================================================================
# LOAD MODELS
# ================================================================

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


# ================================================================
# GET EXACT TRAINING FEATURE ORDER
# ================================================================

if not hasattr(network_imputer, "feature_names_in_"):
    raise RuntimeError(
        "network_imputer.pkl does not contain "
        "feature_names_in_. Cannot safely determine "
        "training feature order."
    )

NETWORK_FEATURES = list(
    network_imputer.feature_names_in_
)


# ================================================================
# MODEL / FEATURE VALIDATION
# ================================================================

print("========================================")
print("CyberGuard Network Detector")
print("========================================")

print(
    f"Network features from imputer: "
    f"{len(NETWORK_FEATURES)}"
)

print(
    f"Network model features: "
    f"{getattr(network_model, 'n_features_in_', 'unknown')}"
)

print(
    f"Bot specialist features: "
    f"{getattr(bot_specialist, 'n_features_in_', 'unknown')}"
)

print("----------------------------------------")
print("EXACT TRAINING FEATURE ORDER")
print("----------------------------------------")

for index, feature in enumerate(
    NETWORK_FEATURES,
    start=1
):
    print(
        f"{index:02d}. {feature}"
    )

print("========================================")


if len(NETWORK_FEATURES) != 65:
    raise RuntimeError(
        f"Expected 65 network features, "
        f"but imputer contains "
        f"{len(NETWORK_FEATURES)} features."
    )


# ================================================================
# LABEL VALIDATION
# ================================================================

print("Network classes:")

for index, label in enumerate(
    label_encoder.classes_
):
    print(
        f"{index:02d}. {label}"
    )

print("========================================")


# ================================================================
# NETWORK ATTACK DETECTOR
# ================================================================

def detect_network_attack(flow_data: dict):

    # ------------------------------------------------------------
    # Validate input type
    # ------------------------------------------------------------

    if not isinstance(flow_data, dict):
        raise ValueError(
            "flow_data must be a JSON object/dictionary."
        )

    # ------------------------------------------------------------
    # Find missing features
    # ------------------------------------------------------------

    missing_features = [
        feature
        for feature in NETWORK_FEATURES
        if feature not in flow_data
    ]

    if missing_features:

        raise ValueError(
            "Missing network features: "
            + ", ".join(missing_features)
        )

    # ------------------------------------------------------------
    # Detect unexpected features
    # ------------------------------------------------------------

    unexpected_features = [
        feature
        for feature in flow_data
        if feature not in NETWORK_FEATURES
    ]

    if unexpected_features:

        print(
            "Warning: unexpected input features:"
        )

        for feature in unexpected_features:
            print(
                f"  - {feature}"
            )

    # ------------------------------------------------------------
    # Build DataFrame in EXACT training order
    # ------------------------------------------------------------

    row = {}

    for feature in NETWORK_FEATURES:
        row[feature] = flow_data[feature]

    X = pd.DataFrame(
        [row],
        columns=NETWORK_FEATURES
    )

    # ------------------------------------------------------------
    # Verify feature order before imputation
    # ------------------------------------------------------------

    actual_order = X.columns.tolist()

    if actual_order != NETWORK_FEATURES:

        raise RuntimeError(
            "Internal feature ordering error. "
            "Input columns do not match the "
            "training feature order."
        )

    # ------------------------------------------------------------
    # Convert all features to numeric
    # ------------------------------------------------------------

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # ------------------------------------------------------------
    # Apply SAME imputer used during training
    # ------------------------------------------------------------

    X_imputed = network_imputer.transform(X)

    # ------------------------------------------------------------
    # Main multiclass Random Forest
    # ------------------------------------------------------------

    probabilities = network_model.predict_proba(
        X_imputed
    )[0]

    predicted_index = int(
        probabilities.argmax()
    )

    predicted_attack = (
        label_encoder.inverse_transform(
            [predicted_index]
        )[0]
    )

    model_score = float(
        probabilities[predicted_index]
    )

    # ------------------------------------------------------------
    # Bot specialist
    # ------------------------------------------------------------

    bot_probabilities = (
        bot_specialist.predict_proba(
            X_imputed
        )[0]
    )

    bot_score = float(
        bot_probabilities[1]
    )

    # ------------------------------------------------------------
    # Bot validation
    # ------------------------------------------------------------

    bot_override = False

    if (
        predicted_attack == "Bot"
        and bot_score < 0.90
    ):

        non_bot_indices = [
            index
            for index, label
            in enumerate(
                label_encoder.classes_
            )
            if label != "Bot"
        ]

        best_non_bot_index = max(
            non_bot_indices,
            key=lambda index:
                probabilities[index]
        )

        predicted_attack = (
            label_encoder.inverse_transform(
                [best_non_bot_index]
            )[0]
        )

        model_score = float(
            probabilities[
                best_non_bot_index
            ]
        )

        bot_override = True

    # ------------------------------------------------------------
    # Return result
    # ------------------------------------------------------------

    return {

        "attack_type": str(
            predicted_attack
        ),

        "model_score": round(
            model_score,
            4
        ),

        "bot_specialist_score": round(
            bot_score,
            4
        ),

        "bot_override": bot_override,

        "is_attack": (
            predicted_attack != "BENIGN"
        )
    }