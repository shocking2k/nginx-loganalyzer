#!/usr/bin/env python3
"""
Automated log collection script for Pantheon sites
Run this via cron to automatically collect and archive logs
"""

import sys
import os
import subprocess
import json
from datetime import datetime

# Add the script directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archive_manager import (
    archive_current_logs,
    cleanup_old_archives,
    DEFAULT_RETENTION_DAYS,
    CURRENT_DIR
)

# Terminus binary path
TERMINUS_BIN = "/opt/homebrew/bin/terminus"

def get_site_list():
    """Get list of all sites from Terminus"""
    try:
        env = os.environ.copy()
        env['TERMINUS_ALLOW_UNSUPPORTED_NEWER_PHP'] = '1'
        result = subprocess.run(
            [TERMINUS_BIN, "site:list", "--format=json"],
            capture_output=True, text=True, check=True, env=env
        )
        sites = json.loads(result.stdout)
        return sorted([v["name"] for v in sites.values()])
    except Exception as e:
        print(f"ERROR: Could not fetch site list: {e}")
        return []

def get_site_uuid(site_name):
    """Get UUID for a site"""
    try:
        env = os.environ.copy()
        env['TERMINUS_ALLOW_UNSUPPORTED_NEWER_PHP'] = '1'
        result = subprocess.run(
            [TERMINUS_BIN, "site:list", "--format=json"],
            capture_output=True, text=True, check=True, env=env
        )
        sites = json.loads(result.stdout)
        return next((k for k, v in sites.items() if v["name"].lower() == site_name.lower()), None)
    except Exception as e:
        print(f"ERROR: Error getting site UUID: {e}")
        return None

def collect_logs_simple(site_uuid, env, site_name):
    """Collect logs without Streamlit dependency"""
    import shutil

    logs_dir = os.path.join(CURRENT_DIR, f"{site_name}_{env}")

    # Archive existing logs if they exist
    if os.path.exists(logs_dir):
        print(f"  Archiving existing logs...")
        try:
            archive_path = archive_current_logs(site_name, env, datetime.now().date())
            if archive_path:
                print(f"  Archived to: {archive_path}")
        except Exception as e:
            print(f"  Warning: Failed to archive logs: {e}")

        # Remove current logs after archiving
        shutil.rmtree(logs_dir)

    # Cleanup old archives
    try:
        deleted_count = cleanup_old_archives(DEFAULT_RETENTION_DAYS)
        if deleted_count > 0:
            print(f"  Cleaned up {deleted_count} old archive(s)")
    except Exception as e:
        print(f"  Warning: Failed to cleanup old archives: {e}")

    os.makedirs(logs_dir, exist_ok=True)

    # Get app servers
    app_servers = subprocess.check_output(
        ["dig", "+short", "-4", f"appserver.{env}.{site_uuid}.drush.in"]
    ).decode().splitlines()

    for server in filter(None, app_servers):
        server_dir = os.path.join(logs_dir, f"app_server_{server}")
        os.makedirs(server_dir, exist_ok=True)

        for log, log_subdir in [("nginx-access.log", "nginx"), ("error.log", "nginx"), ("php-error.log", "php")]:
            cmd = (
                f'echo "get logs/{log_subdir}/{log}" | '
                f'sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o Port=2222 '
                f'{env}.{site_uuid}@{server}'
            )
            print(f"  Downloading {log} from {server}...")
            process = subprocess.Popen(cmd, shell=True, cwd=server_dir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            process.wait()

    print(f"  ✓ Logs collected successfully")

def auto_collect_all_sites():
    """Automatically collect logs for all sites"""

    print(f"[{datetime.now()}] Starting automated log collection...")

    # Get all sites
    sites = get_site_list()
    if not sites:
        print("ERROR: No sites found. Check Terminus authentication.")
        return False

    print(f"Found {len(sites)} sites")

    # Environments to collect (customize as needed)
    environments = ['live']  # Can add 'dev', 'test' if needed

    success_count = 0
    error_count = 0

    for site_name in sites:
        for env in environments:
            try:
                print(f"\n{'='*60}")
                print(f"Collecting: {site_name} ({env})")
                print(f"{'='*60}")

                site_uuid = get_site_uuid(site_name)
                if not site_uuid:
                    print(f"  ERROR: Could not get UUID for {site_name}")
                    error_count += 1
                    continue

                # Collect logs (this automatically archives existing logs)
                collect_logs_simple(site_uuid, env, site_name)

                print(f"  ✓ Success: {site_name} ({env})")
                success_count += 1

            except Exception as e:
                print(f"  ✗ Error collecting {site_name} ({env}): {e}")
                error_count += 1

    # Cleanup old archives
    print(f"\n{'='*60}")
    print("Cleaning up old archives...")
    print(f"{'='*60}")
    try:
        deleted_count = cleanup_old_archives(DEFAULT_RETENTION_DAYS)
        print(f"  Deleted {deleted_count} archive(s) older than {DEFAULT_RETENTION_DAYS} days")
    except Exception as e:
        print(f"  Error during cleanup: {e}")

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"  Successful: {success_count}")
    print(f"  Errors: {error_count}")
    print(f"  Total: {success_count + error_count}")
    print(f"  Completed: {datetime.now()}")

    return error_count == 0

if __name__ == "__main__":
    success = auto_collect_all_sites()
    sys.exit(0 if success else 1)
