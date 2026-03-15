FROM python:3.12-slim

# sqlite3-Binary für eigene Queries + CA-Zertifikate für TLS (IMAP/Graph API)
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nicht-Root-User für Sicherheit
RUN useradd --create-home --shell /bin/bash dmarc
USER dmarc
WORKDIR /home/dmarc/app

# Abhängigkeiten zuerst (Layer-Cache)
COPY --chown=dmarc:dmarc requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Anwendungscode
COPY --chown=dmarc:dmarc dmarc_processor.py dmarc_report.py ./

# Datenbankverzeichnis (Bind-Mount aus docker-compose)
VOLUME ["/data"]

ENV DB_PATH=/data/dmarc_reports.db \
    PATH="/home/dmarc/.local/bin:$PATH" \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "dmarc_processor.py"]
CMD ["--help"]
