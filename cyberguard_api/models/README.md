# Model artifacts

Pickled scikit-learn artifacts for the three CyberGuard pipelines plus their
integrity manifest.

| file | pipeline |
| :--- | :--- |
| `cyberguard_rf_final.pkl`, `cyberguard_preprocessor_final.pkl` | login-attack Random Forest |
| `isolation_forest_model.pkl`, `feature_scaler.pkl` | behavioural anomaly |
| `network_attack_model.pkl`, `bot_specialist_model.pkl`, `network_imputer.pkl`, `network_label_encoder.pkl` | network-flow classification |
| `manifest.json` | SHA-256 digest of every artifact above |
| `*_metadata.json` | training metadata (not loaded at runtime) |

## Integrity (C-4 / M-3)

`joblib.load()` runs arbitrary code while unpickling, so nothing here is loaded
until its SHA-256 matches `manifest.json` — see
`cyberguard_api/services/model_loader.py`.

- **Regenerate** after retraining: `python -m cyberguard_api.services.model_loader --generate`
- **Verify** (strict, use as a startup / CI gate): `python -m cyberguard_api.services.model_loader --check`
- **Separate the digest list from this writable directory in production:** point
  `CYBERGUARD_MODEL_MANIFEST` at a read-only copy of `manifest.json` (mounted
  secret / config store / baked image layer). Then a tampered `.pkl` on the
  writable volume still fails verification.
- Set `CYBERGUARD_VERIFY_MODELS_ON_IMPORT=1` to fail process startup immediately
  on any bad artifact instead of returning per-request 503s.
- **Sign the manifest (PP-M1).** Point `CYBERGUARD_MODEL_MANIFEST_SIG` at an
  Ed25519 detached signature and `CYBERGUARD_MODEL_MANIFEST_PUBKEY` at the public
  key; in production a configured-but-invalid signature is a hard startup failure.

## Serialization compatibility (PP-C5)

`manifest.json` records the `environment` (python / scikit-learn / numpy / scipy /
joblib versions) the `.pkl` files were serialised with. On startup
`check_serialization_env()` compares the running interpreter against it — a
**scikit-learn minor mismatch** (the `_RemainderColsList` / `_fill_dtype` unpickle
hazard) is a warning in dev and a **hard `ModelIntegrityError` in production**.
Regenerate the block on the build image after retraining:
`python -m cyberguard_api.services.model_loader --generate`. To break the version
coupling entirely, export to `skops` / ONNX and load with the restricted loader.

## Storage (L-1)

`.pkl` / `.joblib` files are declared for **Git LFS** in `../.gitattributes`.
Run `git lfs install` once per clone. The artifacts already committed as plain
blobs need a one-time history rewrite to move into LFS
(`git lfs migrate import --include="*.pkl,*.joblib" --everything`) — this rewrites
history and must be coordinated with the team. Do not add new large binaries
without git-lfs installed.
