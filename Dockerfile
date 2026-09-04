# CyberGuard API — reproducible container build (C-1, M-4, A-H1, A-H3, A-L5).
#
# Two stages:
#   builder  — resolves the pinned requirements into a fully HASHED lock and
#              installs it into a venv.
#   runtime  — copies the venv + app, runs a dev-posture import/integrity check,
#              then flips APP_ENV=production for the CMD only.
#
# Pin the base by digest for release builds:
#   docker build --build-arg BASE_DIGEST="@sha256:<digest>" -t cyberguard-api .
# (find it with:  docker buildx imagetools inspect python:3.12-slim)

ARG BASE_DIGEST=
FROM python:3.12-slim${BASE_DIGEST} AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Toolchain for any dependency with no wheel for this platform (psutil / cffi /
# cryptography source fallback, notably on arm64). This is the BUILDER stage only
# — the runtime image is copied from /opt/venv and stays slim.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY cyberguard_api/requirements.txt ./cyberguard_api/requirements.txt
# A-H3: generate a fully resolved, hash-locked requirement set from the pin
# source, then install ONLY that with --require-hashes.
#
# pip-tools 7.4.1 imports pip internals removed in pip >= 25.1
# (PackageFinder.allow_all_prereleases, then stdlib_pkgs) — so pin pip below that
# line for the resolve step. The runtime venv still gets a current pip.
RUN python -m pip install "pip<25.1" \
 && pip install "pip-tools==7.4.1" \
 && pip-compile --quiet --generate-hashes --allow-unsafe \
      --output-file requirements.lock cyberguard_api/requirements.txt \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock


FROM python:3.12-slim${BASE_DIGEST} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    FORWARDED_ALLOW_IPS=127.0.0.1

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/requirements.lock ./requirements.lock
COPY . .

# Build-time verification runs in the DEFAULT (dev) posture — A-H1: the
# production manifest / rate-limit-store env vars are NOT required to build.
RUN python -c "import cyberguard_api.main; print('import OK')" \
 && python -m cyberguard_api.services.model_loader --check

# A-M7 / PP-M1: bake the digest manifest onto a root-owned, world-read-only path
# OUTSIDE the (appuser-writable) model directory. A compromised model volume then
# cannot rewrite its own expected hashes.
RUN mkdir -p /etc/cyberguard \
 && cp cyberguard_api/models/manifest.json /etc/cyberguard/model-manifest.json \
 && chmod 0444 /etc/cyberguard/model-manifest.json \
 && chmod 0555 /etc/cyberguard

# Drop privileges.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

# Runtime posture for the CMD (not the RUN steps above). The model-integrity gate
# runs hard here (CYBERGUARD_VERIFY_MODELS_ON_IMPORT=1) against the baked read-only
# manifest, so a tampered .pkl still aborts startup.
#
# APP_ENV defaults to `staging` so `docker run <image>` (Railway, local, compose)
# boots with no extra config. For a real production deploy set BOTH:
#   -e APP_ENV=production  -e RATE_LIMIT_STORAGE_URI=redis://<host>:6379/0
#   (+ API_KEYS, CORS_ORIGINS — the app fail-closes without them in production)
ENV APP_ENV=staging \
    CYBERGUARD_VERIFY_MODELS_ON_IMPORT=1 \
    CYBERGUARD_MODEL_MANIFEST=/etc/cyberguard/model-manifest.json

EXPOSE 8000

# Readiness gate (M-9 / A-M1): unhealthy until every ML artifact AND the
# telemetry store pass their checks. Honors $PORT (Render / Railway inject it).
HEALTHCHECK --interval=15s --timeout=4s --start-period=30s --retries=5 \
  CMD python -c "import os,sys,urllib.request; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/readyz', timeout=3).status==200 else 1)"

# --proxy-headers + --forwarded-allow-ips: only trust XFF from the ingress (H-6).
#   local / compose : FORWARDED_ALLOW_IPS defaults to 127.0.0.1
#   Render / Railway : set FORWARDED_ALLOW_IPS=* (single managed ingress)
# --no-access-log: the app emits one structured 'request' line per request (A-L2).
# $PORT: platform-assigned port; falls back to 8000 locally.
CMD ["sh", "-c", "exec uvicorn cyberguard_api.main:app --host 0.0.0.0 --port \"${PORT:-8000}\" --proxy-headers --forwarded-allow-ips \"$FORWARDED_ALLOW_IPS\" --no-access-log --no-server-header"]
