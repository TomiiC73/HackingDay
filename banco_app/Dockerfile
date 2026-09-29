# HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).
# Base: imagen oficial de Playwright (trae Python + Chromium + sus dependencias
# de sistema ya instaladas), para el bot CEO headless (bot.py).
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Arranque: sembrar la base (crea ceo_passkey.json para el bot), levantar la app
# y, en paralelo, el bot CEO que revisa su inbox cuando lo disparan.
CMD ["sh", "-c", "python seed.py && (python bot.py &) && python app.py"]
