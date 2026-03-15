FROM python:3.12-slim

# sqlite3-Binary für eigene Queries + CA-Zertifikate für TLS (IMAP/Graph API)
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Abhängigkeiten zuerst (Layer-Cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Anwendungscode
COPY dmarc_processor.py dmarc_report.py ./

# Datenbankverzeichnis (Bind-Mount aus docker-compose)
VOLUME ["/data"]

ENV DB_PATH=/data/dmarc_reports.db \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "dmarc_processor.py"]
CMD ["--help"]
