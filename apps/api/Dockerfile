FROM python:3.13-slim

WORKDIR /app

COPY apps/api/pyproject.toml apps/api/requirements.lock /app/
RUN pip install --no-cache-dir -r requirements.lock \
    && pip install --no-cache-dir 'netmiko>=4.4.0'

COPY apps/api/app /app/app
COPY infra/neo4j /app/infra/neo4j

ENV PYTHONPATH=/app
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
