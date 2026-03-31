# TerraRecon / Nee Tool — Kali Linux base image
FROM kalilinux/kali-rolling

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# ── System update + base dependencies ──────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    golang \
    nmap \
    whatweb \
    testssl.sh \
    feroxbuster \
    nuclei \
    subfinder \
    httpx-toolkit \
    curl \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── katana via Go (nicht in Kali apt verfuegbar) ──────────
ENV PATH="/root/go/bin:${PATH}"
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# ── App setup ─────────────────────────────────────────────
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies (editable install from src layout)
RUN pip3 install --no-cache-dir --break-system-packages -e .

# Ensure output directory exists
RUN mkdir -p /app/output

# ── Environment ───────────────────────────────────────────
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

EXPOSE 8899

CMD ["nee", "web", "--host", "0.0.0.0", "--port", "8899"]
