# MailTrace container image.
#
# Build from the REPOSITORY ROOT, not from this directory, because the image
# needs backend/, frontend/ and samples/ together:
#
#     docker build -f deploy/Dockerfile -t mailtrace .
#     docker run --rm -p 8000:8000 -v mailtrace-data:/app/backend/data mailtrace
#
# The layout inside the image mirrors the repository exactly, because
# app/config.py derives its paths from the package location:
#     BASE_DIR    = /app/backend        (data/, evidence/, the SQLite file)
#     PROJECT_DIR = /app                (frontend/, samples/*.eml)
# Moving either directory without changing config.py will 404 the dashboard.
#
# Unlike a plain `pip install -r requirements.txt` deployment, this image also
# carries the compiled C++20 engine, built against OpenSSL.  The toolchain that
# builds it stays in the builder stage; only the .so reaches the runtime image.
#
# Verified by CI, not by inspection: .github/workflows/ci.yml builds this image
# on every push, starts it, waits for /api/health, analyses a sample through it
# and checks the dashboard is served.  The development machine has no hardware
# virtualisation, so CI is where that happens.

# --------------------------------------------------------------------------- #
# Stage 1: build the virtualenv.  Wheels are resolved here so that pip, its
# cache and any transient build tooling never reach the runtime image.
# --------------------------------------------------------------------------- #
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Every dependency in requirements.txt publishes manylinux wheels, so no
# compiler is installed.  If that ever stops being true the build will fail
# loudly here rather than silently bloating the runtime image.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# The C++20 engine.  Its toolchain is installed only now, so the claim above -
# that requirements.txt resolves to wheels alone - keeps failing loudly if it
# ever stops being true.  build-essential and libssl-dev never leave this
# stage: the compiled extension travels to the runtime image inside /opt/venv.
RUN apt-get update     && apt-get install -y --no-install-recommends build-essential libssl-dev     && rm -rf /var/lib/apt/lists/*

# MAILTRACE_OPENSSL=1 turns an unusable libcrypto into a build failure instead
# of a silent fall back to the built-in SHA-256, so the image cannot quietly
# ship a different hash implementation than the one it claims.
COPY engine/ /tmp/engine/
RUN MAILTRACE_OPENSSL=1 pip install --no-cache-dir /tmp/engine     && rm -rf /tmp/engine     && python -c "import mailtrace_engine as e; assert e.SHA256_BACKEND == 'openssl', e.SHA256_BACKEND; print('engine built,', e.SHA256_BACKEND, 'SHA-256')"

# --------------------------------------------------------------------------- #
# Stage 2: runtime.
# --------------------------------------------------------------------------- #
FROM python:3.13-slim AS runtime

# PORT is a default, not a decision: config.py reads it, and a platform that
# injects its own (Render, Fly, Koyeb) overrides it. MAILTRACE_HOST is set
# explicitly because config.py only defaults to 0.0.0.0 when PORT is present,
# and a container that binds 127.0.0.1 is unreachable from outside.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    MAILTRACE_HOST=0.0.0.0

COPY --from=builder /opt/venv /opt/venv

# python:3.13-slim ships libcrypto.so.3 for its own ssl module, so the engine's
# only non-libc dependency resolves here without apt.  Checked rather than
# assumed: an extension that imports in the builder and not in the runtime is
# exactly the failure this stage exists to catch.
RUN python -c "import hashlib, mailtrace_engine as e; assert e.SHA256_BACKEND == 'openssl', e.SHA256_BACKEND; assert e.sha256(b'mailtrace') == hashlib.sha256(b'mailtrace').hexdigest(); print('engine loads in runtime image,', e.SHA256_BACKEND, 'SHA-256')"

# uid/gid are pinned so a bind-mounted data directory has predictable ownership.
RUN groupadd --gid 10001 mailtrace \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mailtrace

WORKDIR /app

# Source last: dependencies above change rarely, these files change every commit.
COPY --chown=10001:10001 backend/ /app/backend/
COPY --chown=10001:10001 frontend/ /app/frontend/
COPY --chown=10001:10001 samples/ /app/samples/

# The only writable path the service needs: SQLite database, evidence .eml
# files and the cached classifier.  Mount a volume here to keep cases across
# container restarts, or run with MAILTRACE_ZERO_PERSISTENCE=true and it will
# stay empty by design.
RUN mkdir -p /app/backend/data/evidence && chown -R 10001:10001 /app/backend/data
VOLUME ["/app/backend/data"]

USER 10001:10001
WORKDIR /app/backend
EXPOSE 8000

# No curl or wget in python:3.13-slim, and adding either only to poll one URL is
# not worth the surface; the interpreter is already here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,sys,urllib.request; url='http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

# run.py reads app/config.py and starts uvicorn; PID 1 is the interpreter, so
# `docker stop` delivers SIGTERM straight to it.
CMD ["python", "run.py"]
