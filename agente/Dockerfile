# Agente "CEO" del CTF (victima del Stored XSS) — contenedor separado.
# Base: imagen oficial de Playwright (Python + Chromium + dependencias de sistema).
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

# Navegador real que genera la passkey del CEO, la aprovisiona al banco y revisa
# su bandeja (/inbox) periodicamente y cuando lo invitan desde el portal de soporte.
CMD ["python", "agent.py"]
