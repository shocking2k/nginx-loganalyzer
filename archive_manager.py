import os
import gzip
import shutil
import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import re


# Base paths for log storage
LOGS_BASE = os.path.expanduser("~/site-logs")
CURRENT_DIR = os.path.join(LOGS_BASE, "current")
ARCHIVE_DIR = os.path.join(LOGS_BASE, "archive")
INDEX_DIR = os.path.join(LOGS_BASE, "index")
DB_PATH = os.path.join(INDEX_DIR, "logs.db")

# Retention policy (days)
DEFAULT_RETENTION_DAYS = 90


def init_database():
    """Initialize the SQLite database with schema"""
    os.makedirs(INDEX_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Main log entries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            collection_date DATE NOT NULL,
            log_timestamp DATETIME NOT NULL,
            ip_address TEXT NOT NULL,
            status_code INTEGER,
            method TEXT,
            path TEXT,
            user_agent TEXT,
            server TEXT,
            archive_path TEXT NOT NULL
        )
    """)

    # Create indexes for fast searches
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_date ON log_entries(ip_address, log_timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_site_env ON log_entries(site_name, environment)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_collection_date ON log_entries(collection_date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_address ON log_entries(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON log_entries(status_code)")

    # Collections metadata table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            collection_date DATE NOT NULL,
            collection_timestamp DATETIME NOT NULL,
            total_requests INTEGER,
            unique_ips INTEGER,
            file_size_mb REAL,
            compressed_size_mb REAL,
            archive_path TEXT NOT NULL,
            UNIQUE(site_name, environment, collection_date)
        )
    """)

    conn.commit()
    conn.close()


def calculate_file_checksum(file_path):
    """Calculate SHA256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_directory_size_mb(directory):
    """Calculate total size of directory in MB"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)
    return total_size / (1024 * 1024)  # Convert to MB


def compress_log_file(source_path, dest_path):
    """Compress a log file with gzip"""
    with open(source_path, 'rb') as f_in:
        with gzip.open(dest_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)


def batch_parse_nginx_log_for_indexing(log_path):
    """Lightweight parser for database indexing (extract only key fields)"""
    # Nginx log regex pattern (Pantheon format)
    # Note: Pantheon logs have 2 spaces after timestamp bracket
    pattern = re.compile(
        r'(?P<proxy_chain>[\d\., ]+) - - \[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d+) (?P<size>\d+) '
        r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    entries = []
    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                data = match.groupdict()

                # Extract real IP (first in proxy chain)
                proxy_chain = data['proxy_chain']
                ip = proxy_chain.split(',')[0].strip() if proxy_chain else ''

                # Parse timestamp
                try:
                    timestamp = datetime.strptime(data['time'], '%d/%b/%Y:%H:%M:%S %z')
                except:
                    continue

                entries.append({
                    'ip': ip,
                    'timestamp': timestamp,
                    'status': int(data['status']) if data['status'].isdigit() else 0,
                    'method': data['method'],
                    'path': data['path'],
                    'user_agent': data['user_agent']
                })

    return entries


def archive_current_logs(site_name, env, collection_date=None):
    """
    Archive current logs: compress, index to database, and create metadata
    Returns: archive_path if successful, None if no logs to archive
    """
    if collection_date is None:
        collection_date = datetime.now().date()

    # Initialize database if it doesn't exist
    init_database()

    # Check if current logs exist
    current_logs_path = os.path.join(CURRENT_DIR, f"{site_name}_{env}")
    if not os.path.exists(current_logs_path):
        return None  # No logs to archive

    # Create archive directory structure
    archive_site_dir = os.path.join(ARCHIVE_DIR, f"{site_name}_{env}")
    archive_date_dir = os.path.join(archive_site_dir, str(collection_date))

    # If archive already exists for this date, remove it first
    if os.path.exists(archive_date_dir):
        # Make files writable before deletion
        for root, dirs, files in os.walk(archive_date_dir):
            for file in files:
                filepath = os.path.join(root, file)
                os.chmod(filepath, 0o644)  # Make writable
        shutil.rmtree(archive_date_dir)

    os.makedirs(archive_date_dir, exist_ok=True)

    # Calculate original size
    original_size_mb = get_directory_size_mb(current_logs_path)

    # Archive each app server's logs
    metadata = {
        'site_name': site_name,
        'environment': env,
        'collection_date': str(collection_date),
        'collection_timestamp': datetime.now().isoformat(),
        'servers': [],
        'checksums': {}
    }

    total_requests = 0
    unique_ips = set()

    # Process each app server directory
    for server_dir in os.listdir(current_logs_path):
        server_path = os.path.join(current_logs_path, server_dir)
        if not os.path.isdir(server_path):
            continue

        # Create corresponding archive directory
        archive_server_dir = os.path.join(archive_date_dir, server_dir)
        os.makedirs(archive_server_dir, exist_ok=True)

        server_info = {'name': server_dir, 'logs': {}}

        # Compress each log file
        for log_file in os.listdir(server_path):
            source_file = os.path.join(server_path, log_file)
            if not os.path.isfile(source_file):
                continue

            # Calculate checksum before compression
            checksum = calculate_file_checksum(source_file)
            metadata['checksums'][f"{server_dir}/{log_file}"] = checksum

            # Compress the log file
            dest_file = os.path.join(archive_server_dir, f"{log_file}.gz")
            compress_log_file(source_file, dest_file)

            # Set read-only permissions for compliance
            os.chmod(dest_file, 0o444)

            server_info['logs'][log_file] = {
                'checksum': checksum,
                'compressed_path': dest_file
            }

            # Index nginx access logs to database
            if log_file == "nginx-access.log":
                try:
                    entries = batch_parse_nginx_log_for_indexing(source_file)
                    if entries:
                        index_entries_to_database(
                            entries, site_name, env, collection_date,
                            server_dir, dest_file
                        )
                        total_requests += len(entries)
                        unique_ips.update(entry['ip'] for entry in entries)
                except Exception as e:
                    print(f"Error indexing {source_file}: {e}")

        metadata['servers'].append(server_info)

    # Save metadata.json
    metadata_path = os.path.join(archive_date_dir, "metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    # Calculate compressed size
    compressed_size_mb = get_directory_size_mb(archive_date_dir)

    # Record collection in database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO collections
            (site_name, environment, collection_date, collection_timestamp,
             total_requests, unique_ips, file_size_mb, compressed_size_mb, archive_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            site_name, env, str(collection_date), datetime.now().isoformat(),
            total_requests, len(unique_ips), original_size_mb, compressed_size_mb,
            archive_date_dir
        ))
        conn.commit()
    except Exception as e:
        print(f"Error recording collection: {e}")
    finally:
        conn.close()

    return archive_date_dir


def index_entries_to_database(entries, site_name, env, collection_date, server, archive_path):
    """Index log entries to the SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Prepare batch insert
    records = []
    for entry in entries:
        records.append((
            site_name,
            env,
            str(collection_date),
            entry['timestamp'].isoformat(),
            entry['ip'],
            entry['status'],
            entry['method'],
            entry['path'][:500],  # Limit path length
            entry['user_agent'][:500],  # Limit user agent length
            server,
            archive_path
        ))

    # Batch insert for performance
    cursor.executemany("""
        INSERT INTO log_entries
        (site_name, environment, collection_date, log_timestamp, ip_address,
         status_code, method, path, user_agent, server, archive_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, records)

    conn.commit()
    conn.close()


def search_logs_by_ip(ip_address, start_date=None, end_date=None, site_name=None, env=None):
    """
    Search for logs by IP address across all sites or specific site
    Returns: list of matching log entries
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Build query
    query = "SELECT * FROM log_entries WHERE ip_address = ?"
    params = [ip_address.strip()]  # Trim whitespace

    if start_date:
        # Convert date to datetime at start of day
        if hasattr(start_date, 'isoformat'):
            # If it's a date object (not datetime), convert to start of day
            if hasattr(start_date, 'hour'):
                # Already a datetime
                params.append(start_date.isoformat())
            else:
                # It's a date, convert to datetime at 00:00:00
                params.append(f"{start_date.isoformat()}T00:00:00")
        else:
            params.append(start_date)
        query += " AND log_timestamp >= ?"

    if end_date:
        # Convert date to datetime at end of day
        if hasattr(end_date, 'isoformat'):
            # If it's a date object (not datetime), convert to end of day
            if hasattr(end_date, 'hour'):
                # Already a datetime
                params.append(end_date.isoformat())
            else:
                # It's a date, convert to datetime at 23:59:59
                params.append(f"{end_date.isoformat()}T23:59:59")
        else:
            params.append(end_date)
        query += " AND log_timestamp <= ?"

    if site_name:
        query += " AND site_name = ?"
        params.append(site_name)

    if env:
        query += " AND environment = ?"
        params.append(env)

    query += " ORDER BY log_timestamp DESC LIMIT 10000"

    cursor.execute(query, params)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return results


def search_logs_by_date_range(start_date, end_date, site_name=None, env=None, status_codes=None, limit=10000):
    """
    Search for logs by date range with optional filters
    Returns: list of matching log entries
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Convert dates to datetime strings
    if hasattr(start_date, 'isoformat'):
        if hasattr(start_date, 'hour'):
            start_str = start_date.isoformat()
        else:
            start_str = f"{start_date.isoformat()}T00:00:00"
    else:
        start_str = start_date

    if hasattr(end_date, 'isoformat'):
        if hasattr(end_date, 'hour'):
            end_str = end_date.isoformat()
        else:
            end_str = f"{end_date.isoformat()}T23:59:59"
    else:
        end_str = end_date

    # Build query
    query = "SELECT * FROM log_entries WHERE log_timestamp >= ? AND log_timestamp <= ?"
    params = [start_str, end_str]

    if site_name:
        query += " AND site_name = ?"
        params.append(site_name)

    if env:
        query += " AND environment = ?"
        params.append(env)

    if status_codes:
        # status_codes is a list like ['2xx', '4xx']
        status_conditions = []
        for code_range in status_codes:
            if code_range == '2xx':
                status_conditions.append("(status_code >= 200 AND status_code < 300)")
            elif code_range == '3xx':
                status_conditions.append("(status_code >= 300 AND status_code < 400)")
            elif code_range == '4xx':
                status_conditions.append("(status_code >= 400 AND status_code < 500)")
            elif code_range == '5xx':
                status_conditions.append("(status_code >= 500 AND status_code < 600)")

        if status_conditions:
            query += " AND (" + " OR ".join(status_conditions) + ")"

    query += f" ORDER BY log_timestamp DESC LIMIT {limit}"

    cursor.execute(query, params)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return results


def get_archived_collections(site_name=None, env=None):
    """
    Get list of archived collections with metadata
    Returns: list of collection records
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = "SELECT * FROM collections"
    params = []

    if site_name:
        query += " WHERE site_name = ?"
        params.append(site_name)

        if env:
            query += " AND environment = ?"
            params.append(env)
    elif env:
        query += " WHERE environment = ?"
        params.append(env)

    query += " ORDER BY collection_date DESC"

    cursor.execute(query, params)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return results


def cleanup_old_archives(retention_days=DEFAULT_RETENTION_DAYS):
    """
    Remove archives older than retention period
    Returns: number of archives deleted
    """
    cutoff_date = datetime.now().date() - timedelta(days=retention_days)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Find archives to delete
    cursor.execute("""
        SELECT id, archive_path FROM collections
        WHERE collection_date < ?
    """, (str(cutoff_date),))

    archives_to_delete = cursor.fetchall()
    deleted_count = 0

    for archive_id, archive_path in archives_to_delete:
        # Delete files
        if os.path.exists(archive_path):
            try:
                # Make files writable before deletion
                for root, dirs, files in os.walk(archive_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            os.chmod(filepath, 0o644)
                        except:
                            pass  # Ignore if already writable
                shutil.rmtree(archive_path)
                deleted_count += 1
            except Exception as e:
                print(f"Error deleting {archive_path}: {e}")

        # Delete from database
        try:
            cursor.execute("DELETE FROM log_entries WHERE archive_path LIKE ?", (f"{archive_path}%",))
            cursor.execute("DELETE FROM collections WHERE id = ?", (archive_id,))
        except Exception as e:
            print(f"Error deleting database records for {archive_path}: {e}")

    conn.commit()
    conn.close()

    return deleted_count


def get_archive_statistics():
    """
    Get overall archive statistics
    Returns: dict with statistics
    """
    if not os.path.exists(DB_PATH):
        return {
            'total_collections': 0,
            'total_requests': 0,
            'unique_ips': 0,
            'total_size_gb': 0,
            'oldest_date': None,
            'newest_date': None
        }

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get collection stats with COALESCE to handle NULL values
    cursor.execute("""
        SELECT
            COUNT(*) as total_collections,
            COALESCE(SUM(total_requests), 0) as total_requests,
            COALESCE(SUM(compressed_size_mb), 0) as total_size_mb,
            MIN(collection_date) as oldest_date,
            MAX(collection_date) as newest_date
        FROM collections
    """)

    stats = dict(cursor.fetchone())

    # Get unique IPs count (approximate from log_entries)
    cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM log_entries")
    unique_ips_result = cursor.fetchone()
    stats['unique_ips'] = unique_ips_result[0] if unique_ips_result else 0

    # Convert MB to GB - already safe because of COALESCE
    stats['total_size_gb'] = stats['total_size_mb'] / 1024 if stats['total_size_mb'] else 0

    conn.close()

    return stats


def extract_compressed_log(gz_path, output_path):
    """Extract a gzipped log file to a temporary location"""
    with gzip.open(gz_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return output_path
