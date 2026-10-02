FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vault \
    && mkdir -p /app/data && chown vault:vault /app/data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER vault
EXPOSE 8086
# One worker on purpose: sessions and the unlocked master key live in process memory.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8086", "--workers", "1"]
