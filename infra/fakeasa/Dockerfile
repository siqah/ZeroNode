FROM python:3.12-slim

RUN pip install --no-cache-dir "paramiko==3.5.1"

WORKDIR /app
COPY server.py .

EXPOSE 2222
CMD ["python", "server.py"]
