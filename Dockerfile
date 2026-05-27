FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STAGING_MANAGER_CONFIG_DIR=/config \
    STAGING_MANAGER_PORT=7474 \
    RCLONE_CONFIG=/config/rclone/rclone.conf

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl rclone ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py index.html login.html setup.html ./

RUN mkdir -p /config /media \
    && groupadd --system --gid 568 apps \
    && useradd --system --uid 568 --gid 568 --home-dir /config staging-manager \
    && chown -R 568:568 /app /config /media

USER 568:568
EXPOSE 7474
VOLUME ["/config", "/media"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,ssl,urllib.request; https=os.getenv('STAGING_MANAGER_HTTPS','').lower() in ('1','true','yes'); ctx=ssl._create_unverified_context() if https else None; urllib.request.urlopen(('https' if https else 'http') + '://127.0.0.1:7474/api/health', context=ctx, timeout=3)"

CMD ["python", "app.py"]
