FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY run.py .

RUN useradd --system --uid 1000 --home /srv vpnmanager \
    && mkdir -p /data && chown vpnmanager /data
USER vpnmanager

VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import ssl,urllib.request as u;u.urlopen('https://127.0.0.1:8443/health',context=ssl._create_unverified_context(),timeout=4)" || exit 1

CMD ["python", "run.py"]
