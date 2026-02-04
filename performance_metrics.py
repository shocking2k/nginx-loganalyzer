import pandas as pd
import numpy as np

def analyze_response_times(df):
    """
    Analyze response times if available in logs
    Note: Standard nginx access logs don't include response time by default
    If you have $request_time in your log format, this will work
    """
    if 'response_time' in df.columns:
        stats = {
            'avg_response_time': df['response_time'].mean(),
            'median_response_time': df['response_time'].median(),
            'p95_response_time': df['response_time'].quantile(0.95),
            'p99_response_time': df['response_time'].quantile(0.99),
            'max_response_time': df['response_time'].max(),
            'min_response_time': df['response_time'].min()
        }
        return stats
    return None


def identify_slow_endpoints(df, top_n=20):
    """
    Identify endpoints with highest error rates or most requests
    Since we don't have response time, we use error rate as a proxy for performance issues
    """
    endpoint_stats = df.groupby('path').agg({
        'status': ['count', lambda x: (x >= 400).sum(), lambda x: (x >= 500).sum()],
        'ip': 'nunique'
    }).reset_index()

    endpoint_stats.columns = ['Path', 'Total Requests', 'Client Errors (4xx)', 'Server Errors (5xx)', 'Unique IPs']
    endpoint_stats['Error Rate'] = ((endpoint_stats['Client Errors (4xx)'] + endpoint_stats['Server Errors (5xx)']) / endpoint_stats['Total Requests'] * 100).round(2)

    # Sort by total requests to find busiest endpoints
    busiest = endpoint_stats.sort_values('Total Requests', ascending=False).head(top_n)

    # Sort by error rate to find problematic endpoints
    problematic = endpoint_stats[endpoint_stats['Total Requests'] >= 10].sort_values('Error Rate', ascending=False).head(top_n)

    return {
        'busiest_endpoints': busiest,
        'problematic_endpoints': problematic
    }


def analyze_bandwidth_usage(df):
    """
    Analyze bandwidth usage by file type
    Note: Requires 'bytes_sent' field in logs
    """
    if 'bytes_sent' not in df.columns:
        # Try to estimate based on status codes and file types
        return estimate_bandwidth_by_filetype(df)

    bandwidth_stats = df.groupby('extension').agg({
        'bytes_sent': 'sum',
        'path': 'count'
    }).reset_index()

    bandwidth_stats.columns = ['File Type', 'Total Bytes', 'Request Count']
    bandwidth_stats['Total MB'] = (bandwidth_stats['Total Bytes'] / (1024 * 1024)).round(2)
    bandwidth_stats['Avg KB per Request'] = (bandwidth_stats['Total Bytes'] / bandwidth_stats['Request Count'] / 1024).round(2)

    bandwidth_stats = bandwidth_stats.sort_values('Total Bytes', ascending=False)

    return bandwidth_stats[['File Type', 'Total MB', 'Request Count', 'Avg KB per Request']]


def estimate_bandwidth_by_filetype(df):
    """
    Estimate bandwidth when bytes_sent is not available
    Uses typical file size estimates
    """
    # Typical file size estimates in KB
    size_estimates = {
        'jpg': 150, 'jpeg': 150, 'png': 200, 'gif': 50, 'webp': 80,
        'css': 30, 'js': 50,
        'woff': 50, 'woff2': 40, 'ttf': 60, 'otf': 60, 'eot': 50,
        'svg': 10,
        'mp4': 5000, 'webm': 4000, 'avi': 8000,
        'pdf': 500,
        'zip': 2000, 'tar': 3000, 'gz': 1500,
        'json': 5, 'xml': 5,
        'php': 20, 'html': 30,
        '': 20  # Default for pages without extension
    }

    df_copy = df.copy()
    df_copy['estimated_kb'] = df_copy['extension'].map(size_estimates).fillna(20)

    bandwidth_stats = df_copy.groupby('extension').agg({
        'estimated_kb': 'sum',
        'path': 'count'
    }).reset_index()

    bandwidth_stats.columns = ['File Type', 'Estimated Total KB', 'Request Count']
    bandwidth_stats['Estimated Total MB'] = (bandwidth_stats['Estimated Total KB'] / 1024).round(2)
    bandwidth_stats['Avg KB per Request'] = (bandwidth_stats['Estimated Total KB'] / bandwidth_stats['Request Count']).round(2)

    bandwidth_stats = bandwidth_stats.sort_values('Estimated Total KB', ascending=False)

    return bandwidth_stats[['File Type', 'Estimated Total MB', 'Request Count', 'Avg KB per Request']]


def analyze_cache_performance(df):
    """
    Analyze cache hit/miss rates based on status codes and patterns
    200 = potential cache miss, 304 = cache hit (not modified)
    """
    cache_stats = {
        'total_requests': len(df),
        'cache_hits_304': len(df[df['status'] == 304]),
        'potential_cacheable_200': len(df[(df['status'] == 200) & (df['method'] == 'GET')]),
        'cache_hit_rate': 0
    }

    # Calculate cache hit rate
    cacheable_requests = cache_stats['cache_hits_304'] + cache_stats['potential_cacheable_200']
    if cacheable_requests > 0:
        cache_stats['cache_hit_rate'] = (cache_stats['cache_hits_304'] / cacheable_requests * 100)

    # Analyze by file type
    static_extensions = ['jpg', 'jpeg', 'png', 'gif', 'css', 'js', 'woff', 'woff2', 'svg', 'webp', 'ico']
    static_files = df[df['extension'].isin(static_extensions)]

    if not static_files.empty:
        cache_stats['static_total'] = len(static_files)
        cache_stats['static_304'] = len(static_files[static_files['status'] == 304])
        cache_stats['static_cache_rate'] = (cache_stats['static_304'] / cache_stats['static_total'] * 100) if cache_stats['static_total'] > 0 else 0

    return cache_stats


def analyze_request_methods(df):
    """
    Analyze HTTP methods used
    """
    method_stats = df.groupby('method').agg({
        'path': 'count',
        'status': lambda x: (x >= 400).sum()
    }).reset_index()

    method_stats.columns = ['HTTP Method', 'Total Requests', 'Error Count']
    method_stats['Error Rate %'] = (method_stats['Error Count'] / method_stats['Total Requests'] * 100).round(2)

    return method_stats.sort_values('Total Requests', ascending=False)


def analyze_traffic_patterns(df):
    """
    Analyze traffic patterns over time
    """
    if 'time' not in df.columns or df['time'].isnull().all():
        return None

    df_copy = df.copy()
    df_copy['time'] = pd.to_datetime(df_copy['time'], errors='coerce')
    df_copy = df_copy.dropna(subset=['time'])

    if df_copy.empty:
        return None

    # Add time-based columns
    df_copy['hour'] = df_copy['time'].dt.hour
    df_copy['day_of_week'] = df_copy['time'].dt.day_name()
    df_copy['date'] = df_copy['time'].dt.date

    # Requests by hour of day
    hourly = df_copy.groupby('hour').agg({
        'path': 'count',
        'status': lambda x: (x >= 400).sum()
    }).reset_index()
    hourly.columns = ['Hour', 'Requests', 'Errors']

    # Format hour as readable time (e.g., "12:00 AM", "1:00 PM")
    def format_hour(hour):
        if hour == 0:
            return "12:00 AM"
        elif hour < 12:
            return f"{hour}:00 AM"
        elif hour == 12:
            return "12:00 PM"
        else:
            return f"{hour - 12}:00 PM"

    hourly['Hour_Label'] = hourly['Hour'].apply(format_hour)

    # Requests by day of week
    daily = df_copy.groupby('day_of_week').agg({
        'path': 'count',
        'status': lambda x: (x >= 400).sum()
    }).reset_index()
    daily.columns = ['Day of Week', 'Requests', 'Errors']

    # Reorder days properly
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    daily['Day of Week'] = pd.Categorical(daily['Day of Week'], categories=day_order, ordered=True)
    daily = daily.sort_values('Day of Week')

    # Peak traffic times
    peak_hour = hourly.loc[hourly['Requests'].idxmax()]
    low_hour = hourly.loc[hourly['Requests'].idxmin()]

    return {
        'hourly': hourly,
        'daily': daily,
        'peak_hour': int(peak_hour['Hour']),
        'peak_hour_requests': int(peak_hour['Requests']),
        'low_hour': int(low_hour['Hour']),
        'low_hour_requests': int(low_hour['Requests'])
    }


def analyze_status_code_distribution(df):
    """
    Detailed breakdown of status codes
    """
    status_stats = df.groupby('status').agg({
        'path': 'count',
        'ip': 'nunique'
    }).reset_index()

    status_stats.columns = ['Status Code', 'Count', 'Unique IPs']
    status_stats['Percentage'] = (status_stats['Count'] / len(df) * 100).round(2)

    # Add status code descriptions
    status_descriptions = {
        200: 'OK',
        201: 'Created',
        204: 'No Content',
        301: 'Moved Permanently',
        302: 'Found (Redirect)',
        304: 'Not Modified',
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        405: 'Method Not Allowed',
        408: 'Request Timeout',
        429: 'Too Many Requests',
        500: 'Internal Server Error',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout'
    }

    status_stats['Description'] = status_stats['Status Code'].map(status_descriptions).fillna('Other')

    return status_stats.sort_values('Count', ascending=False)


def get_performance_summary(df):
    """
    Get overall performance summary
    """
    total_requests = len(df)
    unique_ips = df['ip'].nunique() if 'ip' in df.columns else 0

    # Calculate success rate
    success_requests = len(df[df['status'] < 400])
    success_rate = (success_requests / total_requests * 100) if total_requests > 0 else 0

    # Calculate error breakdown
    client_errors = len(df[(df['status'] >= 400) & (df['status'] < 500)])
    server_errors = len(df[df['status'] >= 500])

    # Get time range
    time_range = "Unknown"
    if 'time' in df.columns and not df['time'].isnull().all():
        df_copy = df.copy()
        df_copy['time'] = pd.to_datetime(df_copy['time'], errors='coerce')
        df_copy = df_copy.dropna(subset=['time'])
        if not df_copy.empty:
            time_range = f"{df_copy['time'].min()} to {df_copy['time'].max()}"

    summary = {
        'total_requests': total_requests,
        'unique_visitors': unique_ips,
        'success_rate': round(success_rate, 2),
        'client_error_rate': round((client_errors / total_requests * 100), 2) if total_requests > 0 else 0,
        'server_error_rate': round((server_errors / total_requests * 100), 2) if total_requests > 0 else 0,
        'time_range': time_range
    }

    return summary
