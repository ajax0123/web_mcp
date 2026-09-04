"""
network_detector.py
================================================================================
Network-flow attack classification: main multiclass Random Forest validated by a
Bot specialist model.

Audit fixes applied here:
  * M-11 - artifacts are no longer loaded at import time. Call
    `load_network_models()` explicitly (the FastAPI lifespan does), or let
    `detect_network_attack()` lazy-load on first use. Feature values are strictly
    validated: non-numeric / non-finite / wrong-type inputs are rejected with a
    `ValueError` instead of being coerced to NaN and back-filled with the
    training-set median.
  * L-4 - class labels are normalised to ASCII (`Web Attack - Brute Force`,
    not the U+FFFD mojibake baked into the label encoder) and reconciled 1:1
    with both the label encoder's indices and `network_model_metadata.json`.
  * C-4 - every `.pkl` is loaded through `model_loader.load_verified`, which
    checks its SHA-256 against `models/manifest.json` before unpickling.
================================================================================
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
from pathlib import Path

import pandas as pd

from cyberguard_api.services.model_loader import load_verified

_LOG = logging.getLogger("cyberguard.network_detector")

# ================================================================
# PATHS / CONSTANTS
# ================================================================

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"
METADATA_PATH = MODEL_DIR / "network_model_metadata.json"

EXPECTED_FEATURE_COUNT = 65
BOT_SPECIALIST_THRESHOLD = 0.90

# U+FFFD (what the label encoder actually contains) plus the raw CP1252 / Unicode
# en- and em-dash code points, in case a re-fit encoder carries those instead.
_MOJIBAKE_RE = re.compile("\\s*[\ufffd\u0096\u0097\u2013\u2014]+\\s*")
_WS_RE = re.compile(r"\s{2,}")

# ================================================================
# MODULE STATE (populated by load_network_models)
# ================================================================

network_model = None
bot_specialist = None
network_imputer = None
label_encoder = None

NETWORK_FEATURES: list[str] | None = None
CLASS_NAMES: list[str] | None = None

_LOADED = False

# M-12: detect_network_attack() runs in Starlette's *sync* threadpool (the API
# routes are `def`, not `async def`), so lazy initialisation must be guarded by a
# threading primitive — an asyncio.Lock would be bound to a loop these worker
# threads are not on. Re-entrant so a forced reload from within a holder is safe.
_LOAD_LOCK = threading.RLock()


class NetworkModelsUnavailable(RuntimeError):
    """
    Raised when the network models are not initialised or failed to load.

    Subclasses ``RuntimeError`` so the existing
    ``except (ModelIntegrityError, RuntimeError)`` handler in the API layer
    turns it into a clean HTTP 503 rather than a 500 / bare AssertionError.
    """


# ================================================================
# LABEL NORMALISATION (L-4)
# ================================================================

def clean_label(raw: str) -> str:
    """
    Normalise a raw class label to an ASCII-safe canonical form.

    The label encoder was fitted on CICIDS2017 labels whose en-dash was decoded
    to U+FFFD, e.g. ``"Web Attack \\ufffd Brute Force"``. Collapse any run of
    replacement characters (with surrounding space) to ``" - "``. Deterministic;
    a no-op for labels that are already clean.
    """
    cleaned = _MOJIBAKE_RE.sub(" - ", str(raw)).strip()
    return _WS_RE.sub(" ", cleaned)


# ================================================================
# MODEL LOADING (M-11 / C-4)
# ================================================================

def load_network_models(*, force: bool = False) -> None:
    """
    Load and integrity-check the network models, then validate feature and label
    alignment. Idempotent: a second call is a no-op unless ``force=True``.

    Raises
    ------
    ModelIntegrityError
        A `.pkl` is missing from the manifest or fails its SHA-256 check.
    RuntimeError
        Feature count, feature-name metadata, or class-label alignment is wrong.
    """
    global network_model, bot_specialist, network_imputer, label_encoder
    global NETWORK_FEATURES, CLASS_NAMES, _LOADED

    # Fast path — no lock once initialised (a plain bool read is atomic under the
    # GIL and `_LOADED` is written last, after every other global is in place).
    if _LOADED and not force:
        return

    with _LOAD_LOCK:
        # Re-check under the lock: a racing caller may have finished the load
        # while we were blocked here (M-12).
        if _LOADED and not force:
            return

        try:
            # Each artifact is SHA-256 verified against the manifest *before*
            # joblib.load runs (C-4 / M-3). Build into locals and publish the
            # module globals only once every check has passed, so a reader can
            # never observe a half-initialised state.
            _network_model = load_verified("network_attack_model.pkl")
            _bot_specialist = load_verified("bot_specialist_model.pkl")
            _network_imputer = load_verified("network_imputer.pkl")
            _label_encoder = load_verified("network_label_encoder.pkl")

            # ---- feature order ------------------------------------------
            if not hasattr(_network_imputer, "feature_names_in_"):
                raise RuntimeError(
                    "network_imputer.pkl has no feature_names_in_; cannot "
                    "determine the training feature order."
                )
            features = list(_network_imputer.feature_names_in_)
            if len(features) != EXPECTED_FEATURE_COUNT:
                raise RuntimeError(
                    f"expected {EXPECTED_FEATURE_COUNT} network features, imputer "
                    f"has {len(features)}."
                )
            model_features = getattr(_network_model, "n_features_in_", None)
            if model_features not in (None, EXPECTED_FEATURE_COUNT):
                raise RuntimeError(
                    f"network_attack_model expects {model_features} features, "
                    f"imputer provides {EXPECTED_FEATURE_COUNT}."
                )

            # ---- class labels: reconcile encoder <-> metadata 1:1 (L-4) --
            encoder_names = [clean_label(c) for c in _label_encoder.classes_]

            n_model_classes = len(getattr(_network_model, "classes_", encoder_names))
            if n_model_classes != len(encoder_names):
                raise RuntimeError(
                    f"model emits {n_model_classes} classes, label encoder has "
                    f"{len(encoder_names)}."
                )

            try:
                meta = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
                meta_classes = list(meta.get("classes", []))
            except FileNotFoundError:
                meta_classes = []
            if meta_classes:
                meta_clean = [clean_label(c) for c in meta_classes]
                if meta_clean != encoder_names:
                    raise RuntimeError(
                        "network_model_metadata.json 'classes' do not reconcile "
                        f"1:1 with the label encoder.\n  metadata: {meta_clean}\n"
                        f"  encoder : {encoder_names}"
                    )

            # ---- publish (last write is `_LOADED`) --------------------
            network_model = _network_model
            bot_specialist = _bot_specialist
            network_imputer = _network_imputer
            label_encoder = _label_encoder
            NETWORK_FEATURES = features
            CLASS_NAMES = encoder_names
            _LOADED = True
        except BaseException:
            # Never leave partially-initialised module state behind — the next
            # caller must get a clean retry, not a mix of old/new artifacts.
            network_model = None
            bot_specialist = None
            network_imputer = None
            label_encoder = None
            NETWORK_FEATURES = None
            CLASS_NAMES = None
            _LOADED = False
            raise

    _LOG.info(
        "network detector loaded",
        extra={
            "features": len(NETWORK_FEATURES),
            "classes": len(CLASS_NAMES),
            "class_names": CLASS_NAMES,
            "bot_specialist_threshold": BOT_SPECIALIST_THRESHOLD,
        },
    )


def _ensure_loaded() -> None:
    """
    Guarantee the models are initialised or raise ``NetworkModelsUnavailable``.

    Never raises a bare ``AssertionError`` (which ``python -O`` would strip),
    and the load itself is serialised by ``_LOAD_LOCK`` (M-12).
    """
    if not _LOADED:
        load_network_models()
    ready = _LOADED and all(
        obj is not None
        for obj in (
            network_model,
            bot_specialist,
            label_encoder,
            NETWORK_FEATURES,
            CLASS_NAMES,
        )
    )
    if not ready:
        raise NetworkModelsUnavailable("network attack models are not initialised")


# ================================================================
# STRICT INPUT VALIDATION (M-11)
# ================================================================

def _coerce_finite_number(value) -> float:
    """
    Return `value` as a finite float, or raise ValueError.

    Accepts int / float / numeric string. Rejects bool, None, containers,
    NaN, +/-inf, and non-numeric strings. Nothing is silently defaulted.
    """
    if isinstance(value, bool):
        raise ValueError("boolean is not a valid numeric feature value")
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if text == "":
            raise ValueError("empty string is not a number")
        try:
            number = float(text)
        except ValueError:
            raise ValueError(f"non-numeric string {value!r}") from None
    else:
        raise ValueError(f"unsupported type {type(value).__name__}")
    if not math.isfinite(number):
        raise ValueError(f"non-finite value {value!r}")
    return number


def _validate_flow(flow_data: dict) -> dict[str, float]:
    """
    Validate a raw flow record against the training schema.

    Returns a dict of {feature: finite float} for exactly the training features.
    Raises ValueError for a non-dict, missing features, or any value that is not
    a finite number. Unexpected extra keys are reported as a warning only.
    """
    if not isinstance(flow_data, dict):
        raise ValueError("flow_data must be a JSON object / dictionary.")

    # Explicit check instead of `assert` (which `python -O` removes). This maps
    # to HTTP 503, not the 422 that a ValueError would give (M-12).
    if NETWORK_FEATURES is None:
        raise NetworkModelsUnavailable(
            "network feature schema unavailable — models not initialised"
        )

    missing = [f for f in NETWORK_FEATURES if f not in flow_data]
    if missing:
        raise ValueError("missing network features: " + ", ".join(missing))

    unexpected = [k for k in flow_data if k not in NETWORK_FEATURES]
    if unexpected:
        _LOG.warning(
            "ignoring unexpected input features",
            extra={"unexpected_features": [str(k) for k in unexpected]},
        )

    cleaned: dict[str, float] = {}
    errors: dict[str, str] = {}
    for feature in NETWORK_FEATURES:
        try:
            cleaned[feature] = _coerce_finite_number(flow_data[feature])
        except ValueError as exc:
            errors[feature] = str(exc)

    if errors:
        detail = "; ".join(f"{name}: {msg}" for name, msg in errors.items())
        raise ValueError(f"invalid network feature values -> {detail}")

    return cleaned


# ================================================================
# NETWORK ATTACK DETECTOR
# ================================================================

def detect_network_attack(flow_data: dict) -> dict:
    """
    Classify a single network flow.

    Lazy-loads the models on first call. Input is strictly validated; malformed
    or hostile records raise ``ValueError`` (never silently imputed).
    """
    _ensure_loaded()

    cleaned = _validate_flow(flow_data)

    # `_validate_flow` guarantees every training column is present and finite, so
    # the median `SimpleImputer` would be an identity transform. We feed the
    # validated frame straight to the models: M-11 forbids median back-fill of
    # caller input, and this also avoids a brittle imputer<->sklearn coupling.
    X = pd.DataFrame(
        [[cleaned[f] for f in NETWORK_FEATURES]], columns=NETWORK_FEATURES
    ).astype("float64")

    # ---- main multiclass model --------------------------------------
    probabilities = network_model.predict_proba(X)[0]
    final_index = int(probabilities.argmax())

    # ---- bot specialist -------------------------------------------
    bot_probabilities = bot_specialist.predict_proba(X)[0]
    bot_score = float(bot_probabilities[1])

    # ---- bot validation -----------------------------------------
    bot_override = False
    if CLASS_NAMES[final_index] == "Bot" and bot_score < BOT_SPECIALIST_THRESHOLD:
        non_bot_indices = [i for i, name in enumerate(CLASS_NAMES) if name != "Bot"]
        final_index = max(non_bot_indices, key=lambda i: probabilities[i])
        bot_override = True

    predicted_attack = CLASS_NAMES[final_index]
    model_score = float(probabilities[final_index])

    return {
        "attack_type": predicted_attack,                       # canonical ASCII label
        "raw_label": str(label_encoder.classes_[final_index]),  # exact encoder class
        "model_score": round(model_score, 4),
        "bot_specialist_score": round(bot_score, 4),
        "bot_override": bot_override,
        "is_attack": predicted_attack != "BENIGN",
    }
