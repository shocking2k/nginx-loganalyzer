# Multi-stage build for Nginx Log Analyzer
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final stage
FROM python:3.11-slim

# Install runtime dependencies (dig for DNS lookups, openssh-client for SFTP, goaccess for reports)
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    openssh-client \
    goaccess \
    curl \
    php-cli \
    php-xml \
    php-curl \
    php-mbstring \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Terminus CLI V4
RUN curl -L https://github.com/pantheon-systems/terminus/releases/latest/download/terminus.phar -o /usr/local/bin/terminus \
    && chmod +x /usr/local/bin/terminus

RUN mkdir -p /opt/homebrew/bin && ln -s /usr/local/bin/terminus /opt/homebrew/bin/terminus

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Make startup script executable
RUN chmod +x startup.sh

# Create directories for logs and SSH keys
RUN mkdir -p /home/appuser/site-logs /home/appuser/.ssh && \
    chown -R appuser:appuser /home/appuser/site-logs /home/appuser/.ssh

# Switch to non-root user
USER appuser

# Add local Python packages to PATH
ENV PATH=/home/appuser/.local/bin:$PATH


# Expose Streamlit default port
EXPOSE 8501


# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Set Streamlit configuration
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Run the application with startup script
CMD ["./startup.sh"]

