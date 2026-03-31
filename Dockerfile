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
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── katana via prebuilt binary (go install hat CGO-Bug mit Kali-Go) ──
RUN KATANA_VER=$(curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest | grep '"tag_name"' | cut -d'"' -f4) \
    && curl -sL "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VER}/katana_${KATANA_VER#v}_linux_amd64.zip" -o /tmp/katana.zip \
    && unzip /tmp/katana.zip katana -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana \
    && rm /tmp/katana.zip

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
