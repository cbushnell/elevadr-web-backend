# Multi-stage build for optimized image size
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install Zeek and build dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
    && wget -qO - https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | apt-key add - \
    && apt-get update \
    && apt-get install -y zeek \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Final stage
FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install Python and runtime dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Zeek from builder stage
COPY --from=builder /opt/zeek /opt/zeek

# Add Zeek to PATH
ENV PATH="/opt/zeek/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create necessary directories
RUN mkdir -p /app/data/uploads \
    /app/data/zeeks \
    /app/output \
    && chmod -R 755 /app

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PCAP_INPUT=/input/capture.pcap
ENV REPORT_OUTPUT=/output/report.json

# Volume mounts for input/output
VOLUME ["/input", "/output"]

# Entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]
