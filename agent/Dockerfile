# APS Vault update agent (0.38). docker CLI + compose plugin come with the base image, cosign verifies the release
# signatures, python3 runs agent/updater.py (standard library only).
FROM docker:27-cli
RUN apk add --no-cache python3 cosign tzdata && apk upgrade --no-cache
COPY updater.py /app/updater.py
# The agent needs the Docker socket (it recreates the vault's containers) — whoever controls it controls the host.
# That is why it decides on its own what to run: see the module docstring.
ENTRYPOINT ["python3", "/app/updater.py"]
