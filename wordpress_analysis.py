import pandas as pd
import re

def detect_wordpress_patterns(df):
    """
    Detect WordPress-specific patterns in nginx logs
    Returns a dictionary with various WordPress-related metrics
    """
    results = {
        'plugins': [],
        'themes': [],
        'wp_admin_access': pd.DataFrame(),
        'xml_rpc': pd.DataFrame(),
        'wp_login_attempts': pd.DataFrame(),
        'wp_attacks': pd.DataFrame(),
        'update_patterns': pd.DataFrame()
    }

    # Plugin detection - /wp-content/plugins/plugin-name/
    # Only match valid plugin directory names (letters, numbers, hyphens, underscores)
    plugin_pattern = r'/wp-content/plugins/([a-zA-Z0-9_-]+)/'
    # Use str.extract directly to avoid the warning and get clean plugin names
    all_plugin_matches = df['path'].str.extract(plugin_pattern, expand=False)
    all_plugin_matches = all_plugin_matches.dropna()

    # Separate legitimate plugins from suspicious probes
    if not all_plugin_matches.empty:
        # Known malicious patterns to exclude
        malicious_patterns = [
            'ALFA', 'HOKI', 'WSO', 'r57', 'c99', 'b374k',  # Known web shells
            'DATA', 'Shell', 'Backdoor', 'uploader',  # Common in shell names
            'RightNow', 'up.php', 'x.php', 'shell'  # Suspicious patterns
        ]

        # Filter out malicious patterns (case insensitive)
        legitimate = all_plugin_matches.copy()
        for pattern in malicious_patterns:
            legitimate = legitimate[~legitimate.str.contains(pattern, case=False, na=False)]

        # Filter for legitimate plugins (must have hyphen, underscore, or be longer than 10 chars)
        # But NOT all uppercase (which are often shells like ALFA_DATA)
        legitimate = legitimate[
            (
                (legitimate.str.contains(r'[-_]', na=False)) |  # Contains hyphen or underscore
                (legitimate.str.len() > 10)  # Longer names are usually real
            ) &
            (~legitimate.str.isupper())  # Not all uppercase (shells often are)
        ]

        # Filter out .php files from legitimate plugins
        legitimate = legitimate[~legitimate.str.contains(r'\.php$', na=False, regex=True)]

        if not legitimate.empty:
            plugins = legitimate.value_counts()
            results['plugins'] = plugins.reset_index()
            results['plugins'].columns = ['Plugin', 'Request Count']

    # Theme detection - /wp-content/themes/theme-name/
    # Only match valid theme directory names (letters, numbers, hyphens, underscores)
    theme_pattern = r'/wp-content/themes/([a-zA-Z0-9_-]+)/'
    # Use str.extract directly to avoid the warning and get clean theme names
    all_theme_matches = df['path'].str.extract(theme_pattern, expand=False)
    all_theme_matches = all_theme_matches.dropna()

    # Separate legitimate themes from suspicious probes
    if not all_theme_matches.empty:
        # Known malicious patterns to exclude
        malicious_patterns = [
            'ALFA', 'HOKI', 'WSO', 'r57', 'c99', 'b374k',  # Known web shells
            'DATA', 'Shell', 'Backdoor', 'uploader',  # Common in shell names
            'RightNow', 'up.php', 'x.php', 'shell'  # Suspicious patterns
        ]

        # Filter out malicious patterns (case insensitive)
        legitimate = all_theme_matches.copy()
        for pattern in malicious_patterns:
            legitimate = legitimate[~legitimate.str.contains(pattern, case=False, na=False)]

        # Filter for legitimate themes (must have hyphen, underscore, or be longer than 10 chars)
        # But NOT all uppercase (which are often shells like ALFA_DATA)
        legitimate = legitimate[
            (
                (legitimate.str.contains(r'[-_]', na=False)) |  # Contains hyphen or underscore
                (legitimate.str.len() > 10)  # Longer names are usually real
            ) &
            (~legitimate.str.isupper())  # Not all uppercase (shells often are)
        ]

        # Filter out .php files from legitimate themes
        legitimate = legitimate[~legitimate.str.contains(r'\.php$', na=False, regex=True)]

        if not legitimate.empty:
            themes = legitimate.value_counts()
            results['themes'] = themes.reset_index()
            results['themes'].columns = ['Theme', 'Request Count']

    # wp-admin access
    wp_admin = df[df['path'].str.contains('/wp-admin', na=False)]
    if not wp_admin.empty:
        results['wp_admin_access'] = wp_admin[['time', 'ip', 'path', 'status', 'user_agent']].copy()

    # XML-RPC detection (common abuse vector)
    xml_rpc = df[df['path'].str.contains('xmlrpc.php', na=False)]
    if not xml_rpc.empty:
        results['xml_rpc'] = xml_rpc[['time', 'ip', 'path', 'status', 'method']].copy()

    # wp-login.php attempts
    wp_login = df[df['path'].str.contains('wp-login.php', na=False)]
    if not wp_login.empty:
        results['wp_login_attempts'] = wp_login[['time', 'ip', 'path', 'status', 'method']].copy()

    return results


def detect_xml_rpc_abuse(df, threshold=10):
    """
    Detect XML-RPC abuse - high volume requests to xmlrpc.php
    threshold: minimum number of requests to be considered suspicious
    """
    xml_rpc = df[df['path'].str.contains('xmlrpc.php', na=False)]

    if xml_rpc.empty:
        return pd.DataFrame()

    # Group by IP and count requests
    abuse_candidates = xml_rpc.groupby('ip').agg({
        'path': 'count',
        'status': lambda x: (x == 200).sum(),
        'time': ['min', 'max']
    }).reset_index()

    abuse_candidates.columns = ['IP Address', 'Total Requests', 'Successful (200)', 'First Request', 'Last Request']

    # Filter by threshold
    abuse_candidates = abuse_candidates[abuse_candidates['Total Requests'] >= threshold]
    abuse_candidates = abuse_candidates.sort_values('Total Requests', ascending=False)

    return abuse_candidates


def detect_wp_login_brute_force(df, threshold=5):
    """
    Detect brute force attempts on wp-login.php
    threshold: minimum number of failed login attempts
    """
    wp_login = df[df['path'].str.contains('wp-login.php', na=False)]

    if wp_login.empty:
        return pd.DataFrame()

    # Group by IP and look for POST requests (actual login attempts)
    login_attempts = wp_login[wp_login['method'] == 'POST'].groupby('ip').agg({
        'path': 'count',
        'status': lambda x: ((x == 200) | (x == 302)).sum(),  # Success or redirect
        'time': ['min', 'max']
    }).reset_index()

    login_attempts.columns = ['IP Address', 'Login Attempts', 'Successful', 'First Attempt', 'Last Attempt']
    login_attempts['Failed Attempts'] = login_attempts['Login Attempts'] - login_attempts['Successful']

    # Filter by threshold
    brute_force = login_attempts[login_attempts['Failed Attempts'] >= threshold]
    brute_force = brute_force.sort_values('Failed Attempts', ascending=False)

    return brute_force


def detect_wordpress_attacks(df):
    """
    Detect common WordPress attack patterns
    """
    attack_patterns = {
        'Theme Editor Access': r'/wp-admin/theme-editor\.php',
        'Plugin Editor Access': r'/wp-admin/plugin-editor\.php',
        'User Enumeration': r'\?author=\d+',
        'Config File Access': r'wp-config\.php',
        'Backup File Access': r'\.(?:sql|zip|tar|gz|bak)$',
        'Database Export': r'wp-content/.*\.(?:sql|db)',
        'Shell Upload Attempt': r'\.(?:php\d?|phtml|php\.).*$',
        'Traversal Attempt': r'\.\./.*wp-',
        'REST API User Enum': r'/wp-json/wp/v2/users',
        'Admin AJAX Abuse': r'/wp-admin/admin-ajax\.php',
    }

    attack_summary = []

    for attack_type, pattern in attack_patterns.items():
        # Escape pattern if it contains capturing groups, or use non-capturing groups
        matches = df[df['path'].str.contains(pattern, na=False, regex=True, case=False)]
        if not matches.empty:
            attack_summary.append({
                'Attack Type': attack_type,
                'Count': len(matches),
                'Unique IPs': matches['ip'].nunique(),
                'Example Path': matches.iloc[0]['path'] if len(matches) > 0 else ''
            })

    if attack_summary:
        return pd.DataFrame(attack_summary).sort_values('Count', ascending=False)

    return pd.DataFrame()


def detect_update_maintenance_windows(df):
    """
    Detect potential WordPress update/maintenance windows
    Look for wp-cron.php, update-core.php, etc.
    """
    update_patterns = [
        'wp-cron.php',
        'update-core.php',
        'update.php',
        'upgrade.php',
        'wp-admin/update',
    ]

    update_requests = df[df['path'].str.contains('|'.join(update_patterns), na=False, regex=True)]

    if update_requests.empty:
        return pd.DataFrame()

    # Group by time windows (hourly)
    if 'time' in update_requests.columns and not update_requests['time'].isnull().all():
        update_requests_copy = update_requests.copy()
        update_requests_copy['time'] = pd.to_datetime(update_requests_copy['time'], errors='coerce')
        update_requests_copy = update_requests_copy.dropna(subset=['time'])

        if not update_requests_copy.empty:
            update_requests_copy['hour'] = update_requests_copy['time'].dt.floor('h')
            maintenance_windows = update_requests_copy.groupby('hour').agg({
                'path': 'count',
                'ip': 'nunique'
            }).reset_index()
            maintenance_windows.columns = ['Time Window', 'Update Requests', 'Unique IPs']
            return maintenance_windows.sort_values('Update Requests', ascending=False)

    return pd.DataFrame()


def analyze_wp_cron(df):
    """
    Analyze wp-cron.php activity
    """
    wp_cron = df[df['path'].str.contains('wp-cron.php', na=False)]

    if wp_cron.empty:
        return {
            'total_requests': 0,
            'unique_ips': 0,
            'avg_per_hour': 0
        }

    stats = {
        'total_requests': len(wp_cron),
        'unique_ips': wp_cron['ip'].nunique(),
        'avg_per_hour': 0
    }

    # Calculate average per hour if time data available
    if 'time' in wp_cron.columns and not wp_cron['time'].isnull().all():
        wp_cron_copy = wp_cron.copy()
        wp_cron_copy['time'] = pd.to_datetime(wp_cron_copy['time'], errors='coerce')
        wp_cron_copy = wp_cron_copy.dropna(subset=['time'])

        if not wp_cron_copy.empty:
            time_range = (wp_cron_copy['time'].max() - wp_cron_copy['time'].min()).total_seconds() / 3600
            if time_range > 0:
                stats['avg_per_hour'] = len(wp_cron_copy) / time_range

    return stats


def detect_webshell_probes(df):
    """
    Detect attempts to access known web shells and backdoors
    Returns DataFrame with IPs, shell types, and attempt counts
    """
    # Known web shell patterns (name: regex pattern)
    shell_patterns = {
        'ALFA Shell': r'(?i)alfa[_-]?(?:data|shell|teller)',
        'HOKI Shell': r'(?i)hoki[_-]?(?:data|shell)',
        'WSO Shell': r'(?i)wso[_-]?(?:shell|\d)',
        'r57 Shell': r'(?i)r57[_-]?(?:shell)?',
        'c99 Shell': r'(?i)c99[_-]?(?:shell)?',
        'b374k Shell': r'(?i)b374k',
        'FilesMan': r'(?i)filesman',
        'Shell Uploader': r'(?i)(?:up(?:load)?|file)[_-]?(?:manager|man|shell)',
        'RightNow': r'(?i)rightnow',
        'Indi Shell': r'(?i)indi[_-]?(?:shell|shel)',
        'Mini Shell': r'(?i)mini[_-]?(?:shell)',
        'phpSpy': r'(?i)phpspy',
        'Crystal Shell': r'(?i)crystal[_-]?(?:shell|spy)\.php',  # Only match crystal.php or crystalshell.php, not images
        'Webadmin': r'(?i)webadmin\.php',  # Only match .php files
        'Adminer': r'(?i)adminer\.php',
        'PHPMyAdmin Bypass': r'(?i)pma[_-]?(?:shell|bypass)',
        'Generic PHP Shell': r'(?i)(?:shell|cmd|backdoor|backdor)\.php',
        'Obfuscated Shell': r'(?:idx_config|idx_pcon|wp-apxupx|wp-xmlrpc)\.php',
    }

    shell_attempts = []

    for shell_type, pattern in shell_patterns.items():
        matches = df[df['path'].str.contains(pattern, na=False, regex=True)]
        if not matches.empty:
            # Group by IP to see who's scanning
            ip_attempts = matches.groupby('ip').agg({
                'path': ['count', lambda x: list(set(x))[:3]],  # Count and sample paths
                'status': lambda x: list(x.mode()[:1])[0] if len(x.mode()) > 0 else x.iloc[0],  # Most common status
                'time': ['min', 'max']
            }).reset_index()

            ip_attempts.columns = ['IP', 'Attempts', 'Sample Paths', 'Status', 'First Seen', 'Last Seen']
            ip_attempts['Shell Type'] = shell_type

            # Reorder columns
            ip_attempts = ip_attempts[['IP', 'Shell Type', 'Attempts', 'Status', 'First Seen', 'Last Seen', 'Sample Paths']]

            shell_attempts.append(ip_attempts)

    if shell_attempts:
        result = pd.concat(shell_attempts, ignore_index=True)
        result = result.sort_values('Attempts', ascending=False)
        return result

    return pd.DataFrame()


def get_webshell_summary(df):
    """
    Get summary statistics for web shell probe attempts
    """
    shell_probes = detect_webshell_probes(df)

    if shell_probes.empty:
        return {
            'total_attempts': 0,
            'unique_ips': 0,
            'unique_shells': 0,
            'most_targeted': 'N/A'
        }

    summary = {
        'total_attempts': shell_probes['Attempts'].sum(),
        'unique_ips': shell_probes['IP'].nunique(),
        'unique_shells': shell_probes['Shell Type'].nunique(),
        'most_targeted': shell_probes.groupby('Shell Type')['Attempts'].sum().idxmax()
    }

    return summary
