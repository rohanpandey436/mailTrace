
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN apt-get update     && apt-get install -y --no-install-recommends build-essential libssl-dev     && rm -rf /var/lib/apt/lists/*

COPY engine/ /tmp/engine/
RUN MAILTRACE_OPENSSL=1 pip install --no-cache-dir /tmp/engine     && rm -rf /tmp/engine     && python -c "import mailtrace_engine as e; assert e.SHA256_BACKEND == 'openssl', e.SHA256_BACKEND; print('engine built,', e.SHA256_BACKEND, 'SHA-256')"

FROM python:3.13-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    MAILTRACE_HOST=0.0.0.0

COPY --from=builder /opt/venv /opt/venv

RUN python -c "import hashlib, mailtrace_engine as e; assert e.SHA256_BACKEND == 'openssl', e.SHA256_BACKEND; assert e.sha256(b'mailtrace') == hashlib.sha256(b'mailtrace').hexdigest(); print('engine loads in runtime image,', e.SHA256_BACKEND, 'SHA-256')"

# uid/gid are pinned so a bind-mounted data directory has predictable ownership.
RUN groupadd --gid 10001 mailtrace \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mailtrace

WORKDIR /app

# Source last: dependencies above change rarely, these files change every commit.
COPY --chown=10001:10001 backend/ /app/backend/
COPY --chown=10001:10001 frontend/ /app/frontend/
COPY --chown=10001:10001 samples/ /app/samples/

RUN mkdir -p /app/backend/data/evidence && chown -R 10001:10001 /app/backend/data
VOLUME ["/app/backend/data"]

USER 10001:10001
WORKDIR /app/backend
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,sys,urllib.request; url='http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

CMD ["python", "run.py"]
