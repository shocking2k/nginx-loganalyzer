# Nginx Log Analyzer

**A powerful, interactive Streamlit dashboard for analyzing Nginx access logs and PHP error logs, with features for security, performance, and operational insight.**

**Supports Pantheon/Terminus integration for site and environment selection.**

## Features

### Core Analysis Features

- **Site & Environment Dropdowns:** Select Pantheon sites and environments dynamically.
- **Log Collection:** Download logs from all app servers for the selected site/environment.
- **Automated Collection:** Use `auto_collect_logs.py` for cron-based scheduled collection (NEW!)
- **Historical Log Archiving:** Automatically archive logs with 90-day retention for compliance (NEW!)
  - Automatic gzip compression (~90% size reduction)
  - SQLite indexing for instant searches across months of data
  - Immutable archives with SHA256 checksums for audit trails
  - Automatic cleanup of archives older than retention period
- **Cross-Site Search:** Search all sites by IP address and date range across archived logs (NEW!)
- **Log Clearing:** Clear cached logs to start a fresh analysis.
- **Traffic Overview:** Visualize total requests, unique IPs, error rates, and request trends.
- **Request Analysis:** See top paths, status codes, user agents, visitor IPs/hostnames, and top referrers.
- **Error Analysis:** Drill into 4xx/5xx errors and their sources.
- **Security Tab:** Detect suspicious activity (high error rates, 404s, brute-force attempts).
- **File Types Tab:** Analyze top requested file extensions and files, with charts.
- **Bot & Crawler Detection:** Identify bot and crawler activity, including request counts, paths, and error rates.
- **Advanced Security Analysis:**
    - Detects potential brute force attacks.
    - Detects potential SQL injection attempts.
    - Detects potential XSS attacks.
    - **AbuseIPDB Integration:** Check IPs with high error rates against the AbuseIPDB database.
- **Performance Metrics:**
    - Analyze response times (if logs include `$request_time`).
    - Identify busiest and most problematic endpoints by error rate.
    - Analyze bandwidth usage by file type.
    - Analyze cache performance (hit/miss rates).
    - Breakdown of HTTP methods used.
    - Analyze traffic patterns over time (hourly, daily).
    - Detailed status code distribution.
    - Overall performance summary.
- **WordPress Specific Analysis:**
    - Detect installed plugins and themes.
    - Monitor `wp-admin` access.
    - Analyze `xmlrpc.php` activity for potential abuse.
    - Detect `wp-login.php` brute force attempts.
    - Identify various WordPress attack patterns (e.g., theme/plugin editor access, user enumeration, config file access, webshell probes).
    - Detect potential update and maintenance windows.
    - Analyze `wp-cron.php` activity.
- **PHP Error Log Analysis:**
    - View and filter PHP errors by severity (Fatal Error, Warning, Info/Notice).
    - Dropdown filter for error type in the PHP Errors tab.
    - Download PHP error logs as CSV.
- **Downloadable Reports:**
    - Export all log data as CSV.
    - Generate detailed HTML reports using `goaccess`.
- **Standalone Nginx Dashboard:**
    - A separate dashboard to quickly analyze a single Nginx log file.
    - Run with `streamlit run main.py`.

## Requirements

- Python 3.8+
- [Terminus CLI](https://docs.pantheon.io/terminus/install) (for Pantheon integration)
- `dig` (for DNS lookups)
- SFTP access to Pantheon app servers
- [goaccess](https://goaccess.io/download) (for generating HTML reports)

## Python packages

See `requirements.txt`:

```
streamlit
pandas
numpy
plotly
requests
```

Install with:

```
pip install -r requirements.txt
```

## Usage

### Interactive Dashboard

1.  **Clone this repository and install requirements:**
    ```
    git clone https://github.com/curthayman/nginx-loganalyzer.git
    cd nginx-loganalyzer
    pip install -r requirements.txt
    ```
2.  **Ensure you have Terminus installed and authenticated:**
    ```
    terminus auth:login
    ```
3.  **Run the Streamlit app:**
    ```
    streamlit run main.py
    ```

### Automated Log Collection

For automated log collection (ideal for scheduled compliance archiving), use the `auto_collect_logs.py` script:

```bash
# Run manually
python3 auto_collect_logs.py

# Or set up a cron job for daily collection at 2 AM
0 2 * * * /usr/bin/python3 /path/to/auto_collect_logs.py >> /var/log/log-collector.log 2>&1
```

**Features of auto_collect_logs.py:**
- Automatically collects logs from all sites (configurable environments)
- Archives existing logs before collecting new ones
- Compresses archives with gzip (~90% size reduction)
- Indexes logs to SQLite for fast historical searches
- Cleans up archives older than retention period (default: 90 days)
- Provides detailed success/error reporting
- No Streamlit dependency - runs standalone

**Customize environments to collect:**
Edit the `environments` list in the script (default is `['live']`):
```python
environments = ['live', 'test', 'dev']  # Collect from multiple environments
```

## Running with Docker

You can run the Nginx Log Analyzer using Docker, which includes all dependencies (including goaccess).

### Building the Docker Image

```bash
docker build -t nginx-loganalyzer .
```

### Running the Container

**Basic run:**
```bash
docker run -p 8501:8501 nginx-loganalyzer
```

**With Terminus authentication and SSH access:**

To use Pantheon/Terminus integration, you'll need to mount your Terminus configuration and SSH keys:

```bash
docker run -p 8501:8501 \
  -v ~/.terminus:/root/.terminus:ro \
  -v ~/.ssh:/root/.ssh:ro \
  -v ~/site-logs:/root/site-logs \
  nginx-loganalyzer
```

**Explanation of volume mounts:**
- `-v ~/.terminus:/root/.terminus:ro` - Mounts your Terminus configuration (read-only)
- `-v ~/.ssh:/root/.ssh:ro` - Mounts your SSH keys for SFTP access (read-only)
- `-v ~/site-logs:/root/site-logs` - Mounts the logs directory (read-write) so logs persist

### Accessing the Application

Once the container is running, open your browser and navigate to:
```
http://localhost:8501
```

### Docker Notes

- The Docker image includes `goaccess` pre-installed
- Logs are stored in `~/site-logs` by default (mounted as a volume)
- You must have Terminus CLI authenticated on your host machine before running
- SSH keys must be properly configured for Pantheon SFTP access

### Docker Hub

This image is also available on Docker Hub:
```bash
docker pull curthayman/nginx-loganalyzer
docker run -p 8501:8501 \
  -v ~/.terminus:/root/.terminus:ro \
  -v ~/.ssh:/root/.ssh:ro \
  -v ~/site-logs:/root/site-logs \
  curthayman/nginx-loganalyzer
```

## In the sidebar:

- Select a site and environment from the dropdowns.
- Use **Historical Search** to find logs by IP address or date range across all sites.
- Click **"Collect Logs"** to fetch and analyze logs (automatically archives existing logs).
- Click **"Clear Logs"** to remove all downloaded logs.
- Click **"Generate Report"** to create a `goaccess` HTML report.

## Historical Search (NEW!)

The Historical Search feature allows you to search through archived logs for FBI/legal compliance and security investigations:

### How to Use:
1. **Select Date Range:** Choose from presets (Last 7/30/90 Days) or custom range
2. **Search Scope:** Search all sites or just the currently selected site
3. **IP Filter:** Enter an IP address to find all activity from that IP
4. **Status Codes:** Optionally filter by status codes (2xx, 3xx, 4xx, 5xx)
5. **Click "Search Historical Logs"** to query the archive database

### Results:
- Summary statistics (total requests, unique IPs, sites found, date range)
- Preview table with first 1000 results
- Download full results as CSV
- All results include: timestamp, IP, status, method, path, site, environment

### How Archiving Works:
- **Automatic:** Every time you collect new logs, existing logs are automatically archived
- **Compression:** Archives are compressed with gzip (~90% size reduction)
- **Retention:** Archives kept for **90 days** (configurable)
- **Database Index:** SQLite database enables instant IP/date searches without parsing GB of logs
- **Compliance:** Each archive includes metadata.json with SHA256 checksums for audit trails

### Storage Requirements:
- **Per site:** ~1.4GB for 90 days of compressed logs
- **5 sites:** ~7GB for 90 days
- **Database index:** ~1-2GB for 90 days (all sites combined)

### Directory Structure:
```
~/site-logs/
├── current/{site_name}_{env}/          # Active logs (uncompressed)
├── archive/{site_name}_{env}/          # Historical archives
│   ├── 2025-12-18/
│   │   ├── app_server_*/
│   │   │   ├── nginx-access.log.gz
│   │   │   └── php-error.log.gz
│   │   └── metadata.json             # Checksums, timestamps
│   └── 2025-12-17/
└── index/logs.db                       # SQLite search index
```

## Explore the tabs:

- **Overview:** Traffic summary and trends.
- **Requests:** Top paths, status codes, user agents, IPs, referrers.
- **Errors:** All 4xx/5xx errors.
- **Security:** Suspicious activity detection.
- **File Types:** Top file extensions/files, with charts.
- **Bot & Crawler Detection:** Bot and crawler activity breakdown.
- **Advanced Security:** Brute force, SQLi, XSS detection, and AbuseIPDB checks.
- **PHP Errors:**
    - View all PHP errors from all app servers.
    - Filter by Fatal Error, Warning, or Info (Notice) using the dropdown.
    - Download filtered PHP error logs as CSV.
- **WordPress Analysis:** WordPress-specific security and usage analysis.
- **Performance Metrics:** Endpoint performance, bandwidth, cache analysis, traffic patterns.
- **Archive Management (NEW!):**
    - View all archived collections with statistics
    - See storage usage and retention info
    - Manual cleanup of old archives
    - Filter archives by site and environment

## Project Structure

The project consists of several modules for clean separation of concerns:

- **`main.py`** - Main Streamlit dashboard application
- **`archive_manager.py`** - Log archiving, compression, and SQLite indexing
- **`auto_collect_logs.py`** - Automated log collection script (cron-friendly)
- **`log_parser.py`** - Nginx and PHP log parsing functions
- **`analysis.py`** - Security analysis (brute force, SQLi, XSS, AbuseIPDB)
- **`wordpress_analysis.py`** - WordPress-specific attack detection
- **`performance_metrics.py`** - Performance and traffic analysis
- **`terminus.py`** - Pantheon/Terminus API integration
- **`ui.py`** - UI components and report generation

## Customization

- **Log Format:** The parser is tailored for Pantheon Nginx logs with GoAccess-style formatting. If your log format differs, adjust the `parse_nginx_log` function in `log_parser.py`.
- **PHP Error Log Format:** The PHP error parser supports standard PHP error log lines. For custom formats, adjust the `parse_php_error_log` function in `log_parser.py`.
- **Hostname Resolution:** The dashboard attempts to resolve IPs to hostnames; this may be slow for many IPs.
- **Retention Policy:** Default is 90 days. Change `DEFAULT_RETENTION_DAYS` in `archive_manager.py` or use `cleanup_old_archives(days)`.
- **Archive Location:** Default is `~/site-logs/`. Change `LOGS_BASE` in `archive_manager.py` to customize.

## Troubleshooting

- If site or environment dropdowns do not populate, ensure Terminus is installed, authenticated, and in your `PATH`.
- If you see "No valid access logs found," check that logs were collected and are in the expected format.
- If PHP errors do not appear, ensure the `php-error.log` files are present in each app server directory.
- For custom log formats, update the parser as needed.
- If you have questions or want to contribute, open an issue or pull request.
