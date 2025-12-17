# Nginx Log Analyzer

A powerful, interactive Streamlit dashboard for analyzing Nginx access logs and PHP error logs, with integrated security detection and Pantheon/Terminus support.

## Quick Start

```bash
docker pull curthayman/nginx-log-analyzer:latest
docker run -p 8501:8501 curthayman/nginx-log-analyzer:latest
```

Then open your browser to `http://localhost:8501`

## Features

- **Pantheon Integration:** Select sites and environments dynamically via Terminus CLI
- **Log Collection:** Download logs from all app servers for analysis
- **Traffic Overview:** Visualize requests, unique IPs, error rates, and trends
- **Security Analysis:**
  - Brute force attack detection
  - SQL injection attempt detection
  - XSS attack detection
  - AbuseIPDB integration for IP reputation checks
- **Bot & Crawler Detection:** Identify and analyze bot activity
- **PHP Error Log Analysis:** View, filter, and export PHP errors by severity
- **Downloadable Reports:** Export data as CSV or generate HTML reports with GoAccess

## Usage

### Basic Docker Run

```bash
docker run -p 8501:8501 curthayman/nginx-log-analyzer:latest
```

### With Volume Mount (for persistent logs)

```bash
docker run -p 8501:8501 \
  -v ~/site-logs:/root/site-logs \
  curthayman/nginx-log-analyzer:latest
```

### With Terminus Authentication

If you want to use Pantheon/Terminus integration, mount your Terminus config:

```bash
docker run -p 8501:8501 \
  -v ~/.terminus:/root/.terminus \
  -v ~/site-logs:/root/site-logs \
  curthayman/nginx-log-analyzer:latest
```

## Environment Variables

- `ABUSEIPDB_API_KEY`: Optional API key for AbuseIPDB integration (can also be entered in UI)

## Requirements

- Docker
- (Optional) Terminus CLI authentication for Pantheon integration
- (Optional) AbuseIPDB API key for IP reputation checks

## Ports

- **8501**: Streamlit web interface

## Source Code

GitHub: [curthayman/nginx-loganalyzer](https://github.com/curthayman/nginx-loganalyzer)

## Support

For issues, questions, or contributions, please visit the GitHub repository.
