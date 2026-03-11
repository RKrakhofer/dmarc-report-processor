#!/usr/bin/env bash
# Setup: erstellt .venv und installiert Abhängigkeiten
set -e

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt

echo ""
echo "Setup abgeschlossen."
echo "Aktiviere die Umgebung mit: source .venv/bin/activate"
echo "Starte das Script mit:      python dmarc_processor.py"
