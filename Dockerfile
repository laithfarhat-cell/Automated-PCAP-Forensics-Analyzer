# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TERM=xterm-256color

LABEL org.opencontainers.image.title="Automated PCAP Forensics Analyzer" \
      org.opencontainers.image.description="Memory-safe DFIR packet capture analyzer for flow reconstruction, cleartext recovery, DNS tunneling/DGA detection, HTTP file carving, and multi-format reporting." \
      org.opencontainers.image.version="1.0.0"

# Create dedicated non-root analyst user for safe artifact handling
RUN groupadd --gid 1000 dfir \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash dfir \
    && mkdir -p /app /captures /output \
    && chown -R dfir:dfir /app /captures /output

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY pyproject.toml README.md main.py /app/
COPY core /app/core
COPY analyzers /app/analyzers
COPY reporters /app/reporters
COPY data /app/data
COPY scripts /app/scripts

RUN chown -R dfir:dfir /app

USER dfir

VOLUME ["/captures", "/output"]

ENTRYPOINT ["python", "/app/main.py"]
CMD ["--help"]
