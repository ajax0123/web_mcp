"""
model_loader.py
================================================================================
SHA-256-verified loading of pickled model artifacts (audit findings C-4 / M-3).

``joblib.load()`` executes arbitrary code while unpickling, so every artifact
under ``cyberguard_api/models/`` is checked against a committed digest manifest
*before* it is loaded. A missing entry, a missing file, or a checksum mismatch
raises ``ModelIntegrityError`` and the load is aborted.

Separation of the digest list from the writable model store (M-3)
----------------------------------------------------------------------
By default the manifest is the in-tree ``models/manifest.json`` — it sits next
to the ``.pkl`` files it guards, so anyone who can overwrite a model can also
rewrite its expected digest. Set

    CYBERGUARD_MODEL_MANIFEST=/etc/cyberguard/model-manifest.json

to read the expected digests from a location outside the writable model
directory (a read-only mount, a baked image layer, a config store). A tampered
``.pkl`` on a writable volume then still fails verification against the
immutable digest list.

    CYBERGUARD_VERIFY_MODELS_ON_IMPORT=1

makes this module verify **every** manifest artifact at import time and raise
immediately — so a corrupted / tampered pickle halts process startup instead of
surfacing later as a per-request 503.

Regenerate the manifest after intentionally retraining / replacing a model:

    python -m cyberguard_api.services.model_loader --generate
    python -m cyberguard_api.services.model_loader --check      # strict gate
================================================================================
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import joblib

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

# In-tree manifest — the default source and the target of ``--generate``.
_DEFAULT_MANIFEST_PATH = MODEL_DIR / "manifest.json"
# Back-compat module attribute (kept for existing imports / tests).
MANIFEST_PATH = _DEFAULT_MANIFEST_PATH

_READ_CHUNK = 1 << 20  # 1 MiB

_TRUTHY = {"1", "true", "yes", "on"}


class ModelIntegrityError(RuntimeError):
    """Raised when an artifact is missing from the manifest or fails its digest check."""


def resolve_manifest_path() -> Path:
    """
    Path the expected digests are read from.

    ``CYBERGUARD_MODEL_MANIFEST`` (absolute path) wins — use it to keep the
    integrity data off the writable model volume (M-3). Otherwise the in-tree
    ``models/manifest.json``.
    """
    override = os.getenv("CYBERGUARD_MODEL_MANIFEST", "").strip()
    if override:
        return Path(override).expanduser()
    return _DEFAULT_MANIFEST_PATH


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of a file, hex digest."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest() -> dict[str, str]:
    """Read the digest manifest -> {artifact_name: sha256_hex}."""
    manifest_path = resolve_manifest_path()
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:  # pragma: no cover - deployment error
        raise ModelIntegrityError(
            f"model manifest not found: {manifest_path}. "
            "Run `python -m cyberguard_api.services.model_loader --generate` "
            "or set CYBERGUARD_MODEL_MANIFEST."
        ) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ModelIntegrityError(f"malformed manifest JSON: {manifest_path}: {exc}") from exc
    artifacts = data.get("artifacts", data)  # tolerate a bare {name: hash} map
    if not isinstance(artifacts, dict) or not artifacts:
        raise ModelIntegrityError(f"malformed manifest: {manifest_path}")
    return {str(k): str(v).lower() for k, v in artifacts.items()}


def verify_artifact(name: str, manifest: dict[str, str] | None = None) -> Path:
    """
    Confirm ``models/<name>`` exists and its SHA-256 matches the manifest.
    Returns the verified path; raises ``ModelIntegrityError`` on any mismatch.
    """
    manifest = manifest if manifest is not None else load_manifest()
    if name not in manifest:
        raise ModelIntegrityError(f"artifact '{name}' is not listed in the manifest")

    path = MODEL_DIR / name
    if not path.is_file():
        raise ModelIntegrityError(f"artifact file missing: {path}")

    actual = sha256_file(path)
    expected = manifest[name]
    if actual != expected:
        raise ModelIntegrityError(
            f"integrity check FAILED for {name}: "
            f"expected sha256 {expected}, got {actual}. Load aborted."
        )
    return path


def _serialization_env() -> dict[str, str]:
    """Versions that materially affect pickle compatibility (PP-C5 guard)."""
    import platform

    env = {"python": platform.python_version()}
    for mod in ("sklearn", "numpy", "scipy", "joblib"):
        try:
            env[mod] = __import__(mod).__version__
        except Exception:  # pragma: no cover
            env[mod] = "unavailable"
    return env


def check_serialization_env(manifest_full: dict | None = None) -> list[str]:
    """
    Compare the running env against the versions the manifest was generated with.

    A scikit-learn minor mismatch is the known cross-version unpickle hazard
    (``_RemainderColsList`` / ``_fill_dtype``). Returns a list of human-readable
    warnings; in production a scikit-learn minor mismatch is escalated to
    ``ModelIntegrityError`` so the process refuses to start on an incompatible
    interpreter instead of silently degrading to per-request 503s.
    """
    try:
        raw = resolve_manifest_path().read_text(encoding="utf-8")
        recorded = (json.loads(raw) if manifest_full is None else manifest_full).get("environment", {})
    except Exception:  # pragma: no cover
        recorded = {}
    if not recorded:
        return ["manifest has no recorded 'environment' — regenerate with --generate"]

    running = _serialization_env()
    warnings: list[str] = []
    hard = False
    for mod, want in recorded.items():
        have = running.get(mod, "unavailable")
        if want != have:
            warnings.append(f"{mod}: models built with {want}, runtime has {have}")
            if mod == "sklearn" and want.split(".")[:2] != have.split(".")[:2]:
                hard = True
    if hard and _is_production():
        raise ModelIntegrityError(
            "scikit-learn minor version differs from the one the model artifacts "
            f"were serialised with ({'; '.join(warnings)}). Rebuild the artifacts or "
            "pin the runtime — refusing to start (PP-C5)."
        )
    return warnings


def load_verified(name: str, manifest: dict[str, str] | None = None):
    """Verify ``models/<name>`` against the manifest, then ``joblib.load`` it."""
    return joblib.load(verify_artifact(name, manifest))


def verify_all(
    manifest: dict[str, str] | None = None,
    *,
    forbid_unlisted: bool = False,
) -> list[str]:
    """
    Strictly verify every artifact in the manifest (all-or-nothing).

    Raises ``ModelIntegrityError`` on the first missing / mismatched artifact.
    With ``forbid_unlisted`` also fails if a ``*.pkl`` sits in ``MODEL_DIR`` that
    the manifest does not cover (an added rogue artifact is tampering too).
    Returns the list of verified artifact names.
    """
    manifest = manifest if manifest is not None else load_manifest()
    verified: list[str] = []
    for name in sorted(manifest):
        verify_artifact(name, manifest)
        verified.append(name)

    if forbid_unlisted:
        # A-L5: cover both serialisation extensions, not just .pkl.
        on_disk = {p.name for p in MODEL_DIR.glob("*.pkl")} | {
            p.name for p in MODEL_DIR.glob("*.joblib")
        }
        extra = sorted(n for n in on_disk if n not in manifest)
        if extra:
            raise ModelIntegrityError(
                f"unlisted model artifact(s) in {MODEL_DIR} "
                f"(absent from the manifest): {', '.join(extra)}"
            )
    return verified


# Alias — reads better at call sites that mean "gate startup".
verify_manifest = verify_all


def generate_manifest(patterns: tuple[str, ...] = ("*.pkl", "*.joblib")) -> dict[str, str]:
    """Hash every artifact matching ``patterns`` under models/ and write manifest.json.

    Records only version strings (never machine-specific paths) under
    ``environment`` so ``--generate`` on the wrong interpreter cannot bake a
    host path into the source of truth (A-L5).
    """
    paths = sorted({p for pat in patterns for p in MODEL_DIR.glob(pat)})
    artifacts = {path.name: sha256_file(path) for path in paths}
    payload = {
        "algorithm": "sha256",
        "note": (
            "Digests of the pickled model artifacts. verify_artifact() checks a "
            "file against this map before joblib.load() runs (audit findings "
            "C-4 / M-3). For production, serve this file from a read-only path "
            "referenced by CYBERGUARD_MODEL_MANIFEST and sign it (see "
            "CYBERGUARD_MODEL_MANIFEST_SIG)."
        ),
        # Serialisation env at generation time — check_serialization_env() compares
        # the running interpreter against this to catch cross-version unpickle
        # hazards before they surface as request-time 503s (PP-C5).
        "environment": _serialization_env(),
        "artifacts": artifacts,
    }
    # Always write the in-tree copy — you regenerate the source of truth, not a
    # read-only deployment copy.
    _DEFAULT_MANIFEST_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return artifacts


def _is_production() -> bool:
    return os.getenv("APP_ENV", "dev").strip().lower() in {"production", "prod"}


def _looks_writable(path: Path) -> bool:
    """True if the file OR its parent directory is writable by this process (A-M7)."""
    try:
        if path.exists() and os.access(path, os.W_OK):
            return True
        parent = path.parent
        return parent.exists() and os.access(parent, os.W_OK)
    except OSError:  # pragma: no cover
        return True  # can't prove read-only -> treat as writable (fail safe)


def enforce_manifest_location() -> None:
    """
    PP-M1 / A-M7: in production the digest manifest MUST live outside the writable
    model directory AND on a path this process cannot write to, so an attacker who
    can overwrite a ``.pkl`` cannot also rewrite its expected hash.

    Raises ``ModelIntegrityError`` otherwise. No-op outside production. Called from
    the application lifespan (NOT at import — A-H1).
    """
    if not _is_production():
        return
    override = os.getenv("CYBERGUARD_MODEL_MANIFEST", "").strip()
    if not override:
        raise ModelIntegrityError(
            "APP_ENV=production requires CYBERGUARD_MODEL_MANIFEST to point at a "
            "read-only manifest OUTSIDE the model directory (M-3 / PP-M1)."
        )
    try:
        resolved = Path(override).expanduser().resolve()
    except OSError as exc:  # pragma: no cover
        raise ModelIntegrityError(f"cannot resolve CYBERGUARD_MODEL_MANIFEST: {exc}") from exc

    manifest_dir = resolved.parent
    if manifest_dir == MODEL_DIR.resolve() or MODEL_DIR.resolve() in manifest_dir.parents:
        raise ModelIntegrityError(
            f"CYBERGUARD_MODEL_MANIFEST ({override}) resolves inside the writable "
            f"model directory ({MODEL_DIR}). Move it to a read-only path."
        )
    if not resolved.is_file():
        raise ModelIntegrityError(f"CYBERGUARD_MODEL_MANIFEST ({override}) does not exist.")
    if _looks_writable(resolved):
        raise ModelIntegrityError(
            f"CYBERGUARD_MODEL_MANIFEST ({override}) is on a writable path. Mount it "
            "read-only (e.g. a read-only volume / secret mount / baked image layer) "
            "so a compromised model volume cannot rewrite its own digests (A-M7)."
        )


def verify_manifest_signature() -> None:
    """
    Optional detached-signature check on the manifest (M-3 / PP-M1).

    Enabled by setting BOTH:
        CYBERGUARD_MODEL_MANIFEST_SIG      path to an Ed25519 detached signature
        CYBERGUARD_MODEL_MANIFEST_PUBKEY   path to the Ed25519 public key (raw 32B
                                           or PEM SubjectPublicKeyInfo)

    In production, if a signature path is configured the check is mandatory and a
    missing ``cryptography`` dependency is a hard failure.
    """
    sig_path = os.getenv("CYBERGUARD_MODEL_MANIFEST_SIG", "").strip()
    key_path = os.getenv("CYBERGUARD_MODEL_MANIFEST_PUBKEY", "").strip()
    if not sig_path and not key_path:
        return
    if not (sig_path and key_path):
        raise ModelIntegrityError(
            "both CYBERGUARD_MODEL_MANIFEST_SIG and _PUBKEY must be set (or neither)."
        )
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except Exception as exc:  # pragma: no cover
        if _is_production():
            raise ModelIntegrityError(
                f"manifest signature configured but 'cryptography' is unavailable: {exc}"
            ) from exc
        return

    manifest_bytes = resolve_manifest_path().read_bytes()
    sig = Path(sig_path).expanduser().read_bytes()
    key_bytes = Path(key_path).expanduser().read_bytes()
    try:
        pub = load_pem_public_key(key_bytes)  # PEM
        if not isinstance(pub, Ed25519PublicKey):
            raise ModelIntegrityError("manifest pubkey is not Ed25519")
    except ValueError:
        pub = Ed25519PublicKey.from_public_bytes(key_bytes.strip()[:32])
    try:
        pub.verify(sig, manifest_bytes)
    except Exception as exc:
        raise ModelIntegrityError(f"manifest signature verification FAILED: {exc}") from exc


def startup_integrity_gate() -> None:
    """
    Fail-closed integrity gate — call from the application lifespan (A-H1 / A-M6).

    Runs the production posture checks (off-volume + read-only manifest, optional
    signature) and, when ``APP_ENV=production`` OR
    ``CYBERGUARD_VERIFY_MODELS_ON_IMPORT=1``, verifies every manifest artifact and
    re-raises any ``ModelIntegrityError`` FATALLY. A tampered / mismatched pickle
    then halts startup instead of the process degrading to per-request 503s.
    """
    enforce_manifest_location()
    verify_manifest_signature()
    hard = _is_production() or (
        os.getenv("CYBERGUARD_VERIFY_MODELS_ON_IMPORT", "").strip().lower() in _TRUTHY
    )
    if hard:
        verify_all(forbid_unlisted=True)


def _maybe_enforce_on_import() -> None:
    """
    Import-time gate — kept intentionally narrow (A-H1).

    Only the explicit ``CYBERGUARD_VERIFY_MODELS_ON_IMPORT=1`` opt-in runs here.
    The production manifest-location / signature / fail-closed checks moved to
    :func:`startup_integrity_gate`, invoked from ``main.lifespan``, so that
    ``docker build``'s ``python -c "import cyberguard_api.main"`` does not need
    the production manifest env set.
    """
    if os.getenv("CYBERGUARD_VERIFY_MODELS_ON_IMPORT", "").strip().lower() in _TRUTHY:
        verify_all(forbid_unlisted=True)


# Only when imported as a library (a real process starting up) — never when this
# module is run as `python -m ... model_loader --generate/--check`.
if __name__ != "__main__":
    _maybe_enforce_on_import()


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description="model artifact manifest tool")
    parser.add_argument(
        "--generate", action="store_true", help="(re)generate models/manifest.json"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="strictly verify every manifest artifact (startup gate)",
    )
    args = parser.parse_args()

    if args.generate:
        written = generate_manifest()
        print(f"wrote {_DEFAULT_MANIFEST_PATH} with {len(written)} artifacts")
        for name, digest in written.items():
            print(f"  {digest}  {name}")
    elif args.check:
        src = resolve_manifest_path()
        man = load_manifest()
        verify_all(man, forbid_unlisted=True)
        print(f"manifest: {src}")
        for name in sorted(man):
            print(f"OK  {name}")
        print(f"all {len(man)} artifacts verified")
        try:
            if src.resolve().parent == MODEL_DIR.resolve():
                print(
                    "WARNING: the manifest is co-located with the artifacts it "
                    "guards. Set CYBERGUARD_MODEL_MANIFEST to a read-only path to "
                    "separate integrity data from the writable model store (M-3)."
                )
        except OSError:
            pass
    else:
        parser.print_help()
