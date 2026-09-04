"""
tests/test_model_integrity.py
================================================================================
Coverage for the Data-Science / ML-inference remediations:

  * M-3  — SHA-256 verified before joblib.load; digest source separable from the
           writable model dir; tampered pickle rejected.
  * M-12 — lazy network-model init is serialised by a mutex; missing models raise
           a RuntimeError (-> HTTP 503), never a bare AssertionError.

Run:  .venv/bin/pytest tests/test_model_integrity.py
================================================================================
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from cyberguard_api.services import model_loader as ml
from cyberguard_api.services import network_detector as nd


# ===========================================================================
# M-3 — artifact integrity
# ===========================================================================

@pytest.fixture
def fake_models(tmp_path, monkeypatch):
    """A throwaway model dir + in-tree manifest, wired into model_loader."""
    mdir = tmp_path / "models"
    mdir.mkdir()
    art = mdir / "toy_model.pkl"
    art.write_bytes(b"not-a-real-pickle-just-bytes\x00\x01\x02")
    digest = ml.sha256_file(art)
    manifest = mdir / "manifest.json"
    manifest.write_text(json.dumps({"algorithm": "sha256", "artifacts": {"toy_model.pkl": digest}}))

    monkeypatch.setattr(ml, "MODEL_DIR", mdir)
    monkeypatch.setattr(ml, "_DEFAULT_MANIFEST_PATH", manifest)
    monkeypatch.setattr(ml, "MANIFEST_PATH", manifest)
    monkeypatch.delenv("CYBERGUARD_MODEL_MANIFEST", raising=False)
    return {"dir": mdir, "artifact": art, "manifest": manifest, "digest": digest}


def test_clean_artifact_verifies(fake_models):
    assert ml.verify_artifact("toy_model.pkl").name == "toy_model.pkl"
    assert ml.verify_all(forbid_unlisted=True) == ["toy_model.pkl"]


def test_single_byte_tamper_is_rejected(fake_models):
    data = bytearray(fake_models["artifact"].read_bytes())
    data[0] ^= 0x01  # flip one bit of one byte
    fake_models["artifact"].write_bytes(bytes(data))

    with pytest.raises(ml.ModelIntegrityError) as exc:
        ml.verify_artifact("toy_model.pkl")
    assert "integrity check FAILED" in str(exc.value)

    # load_verified must abort *before* joblib.load runs
    with pytest.raises(ml.ModelIntegrityError):
        ml.load_verified("toy_model.pkl")


def test_missing_and_unlisted_artifacts_rejected(fake_models):
    (fake_models["dir"] / "rogue.pkl").write_bytes(b"surprise")
    with pytest.raises(ml.ModelIntegrityError) as exc:
        ml.verify_all(forbid_unlisted=True)
    assert "unlisted" in str(exc.value)

    fake_models["artifact"].unlink()
    with pytest.raises(ml.ModelIntegrityError) as exc:
        ml.verify_artifact("toy_model.pkl")
    assert "missing" in str(exc.value)


def test_manifest_source_is_separable_from_model_dir(fake_models, tmp_path, monkeypatch):
    """CYBERGUARD_MODEL_MANIFEST points verification at a read-only copy (M-3)."""
    external = tmp_path / "ro" / "model-manifest.json"
    external.parent.mkdir()
    external.write_text(fake_models["manifest"].read_text())
    monkeypatch.setenv("CYBERGUARD_MODEL_MANIFEST", str(external))

    assert ml.resolve_manifest_path() == external
    assert ml.verify_artifact("toy_model.pkl").name == "toy_model.pkl"

    # tamper the writable copy -> still caught against the external digest list
    fake_models["artifact"].write_bytes(b"tampered")
    with pytest.raises(ml.ModelIntegrityError):
        ml.verify_artifact("toy_model.pkl")


# ===========================================================================
# M-12 — concurrent lazy load + clean unavailable error
# ===========================================================================

class _FakeEstimator:
    def __init__(self, *, classes=None, n_features=None):
        if classes is not None:
            self.classes_ = list(classes)
        if n_features is not None:
            self.n_features_in_ = n_features

    def predict_proba(self, X):  # pragma: no cover - not exercised here
        import numpy as np
        n = len(getattr(self, "classes_", [0, 1]))
        return np.full((len(X), n), 1.0 / n)


_CLASS_LABELS = [
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
    "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan",
    "SSH-Patator", "Web Attack - Brute Force", "Web Attack - Sql Injection",
    "Web Attack - XSS",
]


@pytest.fixture
def stub_network_load(monkeypatch, tmp_path):
    """Make load_network_models() build from in-memory stubs, counting real loads."""
    calls = {"n": 0}
    feats = [f"f{i}" for i in range(nd.EXPECTED_FEATURE_COUNT)]

    def fake_load_verified(name):
        if name == "network_attack_model.pkl":
            time.sleep(0.03)  # widen the race window
            calls["n"] += 1
            return _FakeEstimator(classes=range(len(_CLASS_LABELS)),
                                  n_features=nd.EXPECTED_FEATURE_COUNT)
        if name == "bot_specialist_model.pkl":
            return _FakeEstimator(classes=[0, 1])
        if name == "network_imputer.pkl":
            class _Imp:
                feature_names_in_ = feats
            return _Imp()
        if name == "network_label_encoder.pkl":
            return _FakeEstimator(classes=_CLASS_LABELS)
        raise AssertionError(name)

    monkeypatch.setattr(nd, "load_verified", fake_load_verified)
    monkeypatch.setattr(nd, "METADATA_PATH", tmp_path / "no-metadata.json")
    # reset module state
    monkeypatch.setattr(nd, "_LOADED", False)
    monkeypatch.setattr(nd, "network_model", None)
    monkeypatch.setattr(nd, "NETWORK_FEATURES", None)
    monkeypatch.setattr(nd, "CLASS_NAMES", None)
    return calls


def test_concurrent_lazy_load_initialises_exactly_once(stub_network_load):
    errors: list[BaseException] = []
    barrier = threading.Barrier(24)

    def worker():
        try:
            barrier.wait()
            nd.load_network_models()          # not force -> double-checked lock
            assert nd._LOADED is True
            assert len(nd.NETWORK_FEATURES) == nd.EXPECTED_FEATURE_COUNT
            assert len(nd.CLASS_NAMES) == len(_CLASS_LABELS)
        except BaseException as exc:  # noqa: BLE001 - collect for the assert below
            errors.append(exc)

    ts = [threading.Thread(target=worker) for _ in range(24)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert not errors, errors
    assert stub_network_load["n"] == 1        # the mutex + re-check let exactly one load through
    assert nd._LOADED is True


def test_validate_flow_without_models_raises_503_error(monkeypatch):
    """No AssertionError (python -O strips those); a RuntimeError -> HTTP 503."""
    monkeypatch.setattr(nd, "NETWORK_FEATURES", None)
    with pytest.raises(nd.NetworkModelsUnavailable) as exc:
        nd._validate_flow({"anything": 1})
    assert isinstance(exc.value, RuntimeError)


def test_ensure_loaded_reports_unavailable(monkeypatch):
    monkeypatch.setattr(nd, "_LOADED", True)          # flag set...
    monkeypatch.setattr(nd, "network_model", None)    # ...but state inconsistent
    monkeypatch.setattr(nd, "load_network_models", lambda **_: None)
    with pytest.raises(nd.NetworkModelsUnavailable):
        nd._ensure_loaded()
