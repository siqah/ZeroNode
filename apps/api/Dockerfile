FROM python:3.12-slim

WORKDIR /app

COPY apps/api/pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir .

COPY apps/api/app /app/app
COPY infra/neo4j /app/infra/neo4j

ENV PYTHONPATH=/app
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
