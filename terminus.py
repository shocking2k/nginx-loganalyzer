import subprocess
import json
import streamlit as st
import os
import shutil
from datetime import datetime
from archive_manager import archive_current_logs, cleanup_old_archives, CURRENT_DIR, DEFAULT_RETENTION_DAYS

# Use full path to terminus binary to ensure it's found when run from Streamlit
TERMINUS_BIN = "/opt/homebrew/bin/terminus"

def get_site_list():
    try:
        env = os.environ.copy()
        env['TERMINUS_ALLOW_UNSUPPORTED_NEWER_PHP'] = '1'
        result = subprocess.run(
            [TERMINUS_BIN, "site:list", "--format=json"],
            capture_output=True, text=True, check=True, env=env
        )
        sites = json.loads(result.stdout)
        return sorted([v["name"] for v in sites.values()])
    except subprocess.CalledProcessError as e:
        st.error(f"Could not fetch site list: {e}")
        st.error(f"STDOUT: {e.stdout}")
        st.error(f"STDERR: {e.stderr}")
        return []
    except Exception as e:
        st.warning(f"Could not fetch site list: {e}")
        return []

def get_env_list(site_name):
    try:
        env = os.environ.copy()
        env['TERMINUS_ALLOW_UNSUPPORTED_NEWER_PHP'] = '1'
        result = subprocess.run(
            [TERMINUS_BIN, "env:list", site_name, "--format=json"],
            capture_output=True, text=True, check=True, env=env
        )
        envs = json.loads(result.stdout)
        return sorted(envs.keys())
    except Exception as e:
        st.warning(f"Could not fetch environment list: {e}")
        return []

def get_site_uuid(site_name):
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
        st.error(f"Error getting site UUID: {str(e)}")
        return None

def collect_logs(site_uuid, env, site_name):
    # Use new directory structure: ~/site-logs/current/{site}_{env}
    logs_dir = os.path.join(CURRENT_DIR, f"{site_name}_{env}")

    # Archive existing logs if they exist (automatic archiving)
    if os.path.exists(logs_dir):
        yield "Archiving existing logs..."
        try:
            archive_path = archive_current_logs(site_name, env, datetime.now().date())
            if archive_path:
                yield f"Archived logs to: {archive_path}"
        except Exception as e:
            yield f"Warning: Failed to archive logs: {e}"

        # Remove current logs after archiving
        shutil.rmtree(logs_dir)

    # Cleanup old archives (older than retention period)
    try:
        deleted_count = cleanup_old_archives(DEFAULT_RETENTION_DAYS)
        if deleted_count > 0:
            yield f"Cleaned up {deleted_count} old archive(s) (>{DEFAULT_RETENTION_DAYS} days)"
    except Exception as e:
        yield f"Warning: Failed to cleanup old archives: {e}"

    os.makedirs(logs_dir, exist_ok=True)

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
            yield f"Connecting to {server} for {log}..."
            process = subprocess.Popen(cmd, shell=True, cwd=server_dir, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                if "Warning: Permanently added" in line:
                    continue
                if "Connected to" in line or "Fetching" in line or "sftp>" in line or log in line or "100%" in line:
                    yield f"[{server}] {line.strip()}"
            process.wait()
            yield f"[{server}] Finished {log}"
