# HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).
# El banco ya no necesita Chromium (el agente CEO vive en su propio contenedor),
# asi que usa una base liviana de Python.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Arranque: sembrar la base (CEO sin credencial; la aprovisiona el agente) y
# levantar la app. El bot/agente ya NO corre aca.
CMD ["sh", "-c", "python seed.py && python app.py"]
