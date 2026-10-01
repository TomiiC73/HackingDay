# Portal interno de soporte del CTF — sitio simple en otro puerto (:5001).
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY soporte.py .
COPY templates ./templates

EXPOSE 5001

CMD ["python", "soporte.py"]
