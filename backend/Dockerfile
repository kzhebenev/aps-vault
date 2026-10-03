FROM python:3.11-slim
WORKDIR /app
# softhsm2: a PKCS#11 software token for the HSM path (hsm.py) — dev/test and small installs;
# production points VAULT_PKCS11_MODULE at the vendor's library instead. Tokens live in the
# data volume (SOFTHSM2_CONF below) so they survive restarts and are backed up with it.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates softhsm2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vault \
    && mkdir -p /app/data && chown vault:vault /app/data \
    && printf "directories.tokendir = /app/data/softhsm\nobjectstore.backend = file\n" > /app/softhsm2.conf \
    && chmod 644 /app/softhsm2.conf
# /etc/softhsm is root-only in the Debian package; the config must be readable by uid 10001
ENV SOFTHSM2_CONF=/app/softhsm2.conf
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER vault
EXPOSE 8086
# One worker on purpose: sessions and the unlocked master key live in process memory.
# h11 parser: HashiCorp clients use the non-standard LIST method, which httptools rejects
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8086", "--workers", "1", "--http", "h11"]
