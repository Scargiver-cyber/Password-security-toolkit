FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/

# Vault data directory (mount a volume here to persist your vault)
RUN mkdir -p /app/data

# VAULT_PATH tells the app where to store the encrypted vault file.
# Override it by passing -e VAULT_PATH=/your/path to docker run, or
# set it in docker-compose.yml. The default keeps data inside the container.
ENV VAULT_PATH=/app/data

EXPOSE 8501

WORKDIR /app/src

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

CMD ["streamlit", "run", "app.py", "--server.headless", "true", "--server.address", "0.0.0.0"]
