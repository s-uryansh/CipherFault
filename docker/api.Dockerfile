FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir ".[api]"

CMD ["sh", "-c", "uvicorn cipherfault.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
