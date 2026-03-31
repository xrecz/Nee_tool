# TerraRecon / Nee Tool — Kali Linux base image
FROM kalilinux/kali-rolling

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# ── System update + base dependencies ──────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3 \
    python3-pip \
    python3-dev \
    # Go (needed for projectdiscovery tools if not in apt)
    golang \
    # Core recon tools (available in Kali repos)
    nmap \
    whatweb \
    testssl.sh \
    feroxbuster \
    # Kali web tools meta-package (includes httpx-toolkit, etc.)
    # kali-tools-web \   ← optional full meta-package (~many GB); use targeted installs below
    # ProjectDiscovery tools — available via apt in Kali
    nuclei \
    subfinder \
    httpx-toolkit \
    katana \
    # Misc utils
    curl \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Fallback: install ProjectDiscovery tools via Go if apt versions are outdated ──
# Uncomment the block below if apt versions are too old:
#
# ENV PATH="/root/go/bin:${PATH}"
# RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
#  && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
#  && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
#  && go install -v github.com/projectdiscovery/katana/cmd/katana@latest

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
