FROM python:3.15-slim
RUN useradd -r -u 10001 nexus
WORKDIR /app
COPY pyproject.toml README.md ./
COPY nexus_shield ./nexus_shield
RUN pip install --no-cache-dir .
USER nexus
WORKDIR /data
ENTRYPOINT ["nexus-shield"]
