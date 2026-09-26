# HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).
# Imagen independiente: Flask + SQLite + cryptography (ECDSA P-256).
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# seed.py borra y recrea la base en cada arranque (genera claves nuevas y
# resiembra alumno/ceo/senuelos): el contenedor siempre empieza limpio, ideal
# para resetear el entorno entre participantes del evento.
CMD ["sh", "-c", "python seed.py && python app.py"]
