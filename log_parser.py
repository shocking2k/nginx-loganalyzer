import re
import gzip
from datetime import datetime
import pandas as pd
import streamlit as st

@st.cache_data
def parse_nginx_log(log_path):
    ip_regex = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[a-fA-F0-9:]+$")  # IPv4 or IPv6

    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()

        parsed_data = []
        for line in lines:
            try:
                quoted = re.findall(r'"([^"]*)"', line)
                bracketed = re.findall(r'\[([^\]]+)\]', line)
                if len(quoted) < 4 or len(bracketed) < 1:
                    continue

                time_str = bracketed[0]
                request = quoted[0]
                referrer = quoted[1]
                user_agent = quoted[2]
                proxy_chain = quoted[3]

                status_match = re.search(r'"\s*(\d{3})\s+(\d+)\s', line)
                if status_match:
                    status = int(status_match.group(1))
                    size = int(status_match.group(2))
                else:
                    status = None
                    size = None

                req_time_match = re.search(r'" ([\d\.]+) "', line)
                req_time = req_time_match.group(1) if req_time_match else None

                method, path, protocol = ('', '', '')
                req_parts = request.split()
                if len(req_parts) == 3:
                    method, path, protocol = req_parts

                try:
                    time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
                except Exception:
                    time = None

                real_ip = proxy_chain.split(',')[0].strip() if proxy_chain else '-'
                ip = real_ip if ip_regex.match(real_ip) else '-'

                parsed_data.append({
                    'ip': ip,
                    'time': time,
                    'method': method,
                    'path': path,
                    'protocol': protocol,
                    'status': status,
                    'size': size,
                    'referrer': referrer,
                    'user_agent': user_agent,
                    'req_time': req_time,
                    'proxy_chain': proxy_chain
                })
            except Exception as e:
                continue
        df = pd.DataFrame(parsed_data)
        if not df.empty:
            df['status'] = pd.to_numeric(df['status'], errors='coerce')
        return df
    except Exception as e:
        st.warning(f"Couldn't parse {log_path}: {str(e)}")
        return pd.DataFrame()

@st.cache_data
def parse_compressed_nginx_log(gz_path):
    """Parse a gzipped nginx log file"""
    ip_regex = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[a-fA-F0-9:]+$")  # IPv4 or IPv6

    try:
        with gzip.open(gz_path, 'rt', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        parsed_data = []
        for line in lines:
            try:
                quoted = re.findall(r'"([^"]*)"', line)
                bracketed = re.findall(r'\[([^\]]+)\]', line)
                if len(quoted) < 4 or len(bracketed) < 1:
                    continue

                time_str = bracketed[0]
                request = quoted[0]
                referrer = quoted[1]
                user_agent = quoted[2]
                proxy_chain = quoted[3]

                status_match = re.search(r'"\s*(\d{3})\s+(\d+)\s', line)
                if status_match:
                    status = int(status_match.group(1))
                    size = int(status_match.group(2))
                else:
                    status = None
                    size = None

                req_time_match = re.search(r'" ([\d\.]+) "', line)
                req_time = req_time_match.group(1) if req_time_match else None

                method, path, protocol = ('', '', '')
                req_parts = request.split()
                if len(req_parts) == 3:
                    method, path, protocol = req_parts

                try:
                    time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
                except Exception:
                    time = None

                real_ip = proxy_chain.split(',')[0].strip() if proxy_chain else '-'
                ip = real_ip if ip_regex.match(real_ip) else '-'

                parsed_data.append({
                    'ip': ip,
                    'time': time,
                    'method': method,
                    'path': path,
                    'protocol': protocol,
                    'status': status,
                    'size': size,
                    'referrer': referrer,
                    'user_agent': user_agent,
                    'req_time': req_time,
                    'proxy_chain': proxy_chain
                })
            except Exception as e:
                continue
        df = pd.DataFrame(parsed_data)
        if not df.empty:
            df['status'] = pd.to_numeric(df['status'], errors='coerce')
        return df
    except Exception as e:
        st.warning(f"Couldn't parse {gz_path}: {str(e)}")
        return pd.DataFrame()

@st.cache_data
def parse_php_error_log(log_path):
    pattern = re.compile(r'\[(.*?)\]\s+PHP\s+([A-Za-z ]+):\s*(.*)')
    parsed = []
    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = pattern.match(line)
            if m:
                time_str, error_type, message = m.groups()
                error_type = error_type.strip().lower()
                if error_type == "fatal error":
                    error_type_label = "Fatal Error (Critical)"
                elif error_type == "warning":
                    error_type_label = "Warning"
                elif error_type == "notice":
                    error_type_label = "Info"
                else:
                    error_type_label = error_type.capitalize()
                parsed.append({
                    'time': time_str,
                    'type': error_type_label,
                    'message': message
                })
    return pd.DataFrame(parsed)
