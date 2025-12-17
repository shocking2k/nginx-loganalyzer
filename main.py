import os
import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
import shutil

from log_parser import parse_nginx_log, parse_php_error_log
from analysis import detect_brute_force, detect_sql_injection, detect_xss, check_abuseipdb
from terminus import get_site_list, get_env_list, get_site_uuid, collect_logs
from ui import generate_goaccess_report
from wordpress_analysis import (detect_wordpress_patterns, detect_xml_rpc_abuse,
                                 detect_wp_login_brute_force, detect_wordpress_attacks,
                                 detect_update_maintenance_windows, analyze_wp_cron,
                                 detect_webshell_probes, get_webshell_summary)
from performance_metrics import (identify_slow_endpoints, analyze_bandwidth_usage,
                                  analyze_cache_performance, analyze_request_methods,
                                  analyze_traffic_patterns, analyze_status_code_distribution,
                                  get_performance_summary)

st.set_page_config(layout="wide", page_title="Nginx Log Analyzer V2")
st.title("📊Nginx Log Analyzer V2")
st.markdown("""
<style>
    .stProgress > div > div > div > div {
        background-color: #1DA1F2;
    }
</style>
""", unsafe_allow_html=True)

logs_dir = None
if 'site_name' in st.session_state and 'env' in st.session_state:
    logs_dir = os.path.expanduser(f"~/site-logs/{st.session_state['site_name']}_{st.session_state['env']}")

with st.sidebar:
    st.header("Configuration")

    if "site_list" not in st.session_state:
        with st.spinner("Retrieving site names..."):
            st.session_state["site_list"] = get_site_list()
    site_list = st.session_state["site_list"]
    if site_list:
        site_name = st.selectbox("Site Name", site_list, key="site_name_select")
    else:
        site_name = st.text_input("Site Name (manual entry)")

    if site_name:
        env_cache_key = f"env_list_{site_name}"
        if env_cache_key not in st.session_state:
            with st.spinner("Retrieving environments..."):
                st.session_state[env_cache_key] = get_env_list(site_name)
        env_list = st.session_state[env_cache_key]
    else:
        env_list = []
    if env_list:
        env = st.selectbox("Environment", env_list, key="env_select")
    else:
        env = st.text_input("Environment (manual entry)")

    st.session_state['abuseipdb_api_key'] = st.text_input("AbuseIPDB API Key (Optional)", type="password", help="Get your API key at https://www.abuseipdb.com/register")

    log_container = st.container()

    col1, col2 = st.columns(2)
    if col1.button("Collect Logs"):
        with st.spinner("Collecting logs..."):
            site_uuid = get_site_uuid(site_name)
            if site_uuid:
                log_lines = []
                with log_container:
                    st.markdown("#### Raw Output: Log Collecting")
                    log_progress = st.empty()
                    for output in collect_logs(site_uuid, env, site_name):
                        log_lines.append(output)
                        log_progress.code('\n'.join(log_lines[-10:]), language="bash")
                st.session_state['site_name'] = site_name
                st.session_state['env'] = env
                st.success("Log collection complete!")
            else:
                st.error("Invalid site name")

    if col2.button("Clear Logs"):
        logs_dir_temp = os.path.expanduser(f"~/site-logs")
        if os.path.exists(logs_dir_temp):
            try:
                # Delete only the contents of the directory, not the directory itself
                for item in os.listdir(logs_dir_temp):
                    item_path = os.path.join(logs_dir_temp, item)
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                st.success("Logs have been cleared successfully!")
                if 'site_name' in st.session_state:
                    del st.session_state['site_name']
                if 'env' in st.session_state:
                    del st.session_state['env']
            except Exception as e:
                st.error(f"Failed to clear logs: {str(e)}")
        else:
            st.warning("No logs directory found to clear.")

    if st.button("Generate Report"):
        if logs_dir and os.path.exists(logs_dir):
            combined_log_path = os.path.join(logs_dir, "combined_nginx_access.log")
            with open(combined_log_path, 'w') as outfile:
                for server_dir in os.listdir(logs_dir):
                    log_path = os.path.join(logs_dir, server_dir, "nginx-access.log")
                    if os.path.exists(log_path):
                        with open(log_path, 'r') as infile:
                            outfile.write(infile.read())

            report_path = os.path.join(logs_dir, "report.html")
            generate_goaccess_report(combined_log_path, report_path)

            if os.path.exists(report_path):
                with open(report_path, "rb") as file:
                    btn = st.download_button(
                        label="Download Report",
                        data=file,
                        file_name="report.html",
                        mime="text/html"
                    )
        else:
            st.warning("No logs directory found to generate report from.")

logs_dir = None
if 'site_name' in st.session_state and 'env' in st.session_state:
    logs_dir = os.path.expanduser(f"~/site-logs/{st.session_state['site_name']}_{st.session_state['env']}")

if logs_dir and os.path.exists(logs_dir):
    if 'site_name' in st.session_state and st.session_state['site_name']:
        env_display = st.session_state['env'] if 'env' in st.session_state else ''
        st.info(f"Currently displaying logs for: **{st.session_state['site_name']}** ({env_display})")
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10 = st.tabs(
        ["Overview", "Requests", "Errors", "Security", "File Types", "Bot & Crawler Detection",
         "Advanced Security", "PHP Errors", "WordPress Analysis", "Performance Metrics"])

    all_logs = []
    php_error_logs = []
    for server_dir in os.listdir(logs_dir):
        log_path = os.path.join(logs_dir, server_dir, "nginx-access.log")
        if os.path.exists(log_path):
            df = parse_nginx_log(log_path)
            if not df.empty:
                df['server'] = server_dir
                all_logs.append(df)
        # Corrected path for PHP error log
        php_log_path = os.path.join(logs_dir, server_dir, "php-error.log")
        if os.path.exists(php_log_path):
            php_df = parse_php_error_log(php_log_path)
            if not php_df.empty:
                php_df['server'] = server_dir
                php_error_logs.append(php_df)

    # --- OVERVIEW TAB ---
    if all_logs:
        df = pd.concat(all_logs, ignore_index=True)
        df['time'] = pd.to_datetime(df['time'], errors='coerce')
        df['status'] = pd.to_numeric(df['status'], errors='coerce')

        def get_extension(path):
            if not isinstance(path, str):
                return ""
            path = path.split('?', 1)[0]
            if '.' in path.split('/')[-1]:
                return path.split('.')[-1].lower()
            return ""

        df['extension'] = df['path'].apply(get_extension)

        with tab1:
            st.header("Traffic Overview")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Requests", len(df))
            with col2:
                st.metric("Unique IPs", df['ip'].nunique())
            with col3:
                st.metric("Error Rate", f"{len(df[df['status'] >= 400]) / len(df):.1%}")
            if not df['time'].isnull().all():
                time_df = df.set_index('time').resample('h').agg({
                    'ip': 'count',
                    'status': lambda x: (x >= 400).sum()
                }).rename(columns={'ip': 'requests', 'status': 'errors'})
                fig = px.area(time_df, x=time_df.index, y=['requests', 'errors'],
                              title="Requests Over Time")
                st.plotly_chart(fig, width='stretch')
            else:
                st.info("No valid timestamps in logs for time series chart.")
            st.download_button(
                label="Download All Log Data as CSV",
                data=df.to_csv(index=False),
                file_name="nginx_logs.csv",
                mime="text/csv"
            )

        with tab2:
            st.header("Request Analysis")
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Top Paths")
                top_paths = df['path'].value_counts().head(10).reset_index()
                top_paths.columns = ['Path', 'Count']
                st.dataframe(top_paths, width='stretch')
            with col2:
                st.subheader("Status Codes")
                top_status = df['status'].value_counts().head(10).reset_index()
                top_status.columns = ['Status', 'Count']
                st.dataframe(top_status, width='stretch')
            st.subheader("User Agents")
            top_agents = df['user_agent'].value_counts().head(10).reset_index()
            top_agents.columns = ['User Agent', 'Count']
            st.dataframe(top_agents, width='stretch')
            st.subheader("Visitor Hostnames and IPs")
            top_ips = df['ip'].value_counts().head(10).reset_index()
            top_ips.columns = ['IP Address', 'Count']

            def resolve_hostname(ip):
                try:
                    import socket
                    return socket.gethostbyaddr(ip)[0]
                except Exception:
                    return "N/A"

            top_ips['Hostname'] = top_ips['IP Address'].apply(resolve_hostname)
            st.dataframe(top_ips[['IP Address', 'Hostname', 'Count']], width='stretch')
            st.subheader("Top Referrers")
            top_referrers = df['referrer'].value_counts().head(10).reset_index()
            top_referrers.columns = ['Referrer', 'Count']
            top_referrers['Referrer'] = top_referrers['Referrer'].replace('-', '[root]')
            st.dataframe(top_referrers, width='stretch')

        with tab3:
            st.header("Error Analysis")
            error_df = df[df['status'] >= 400]
            if not error_df.empty:
                display_cols = ['time', 'status', 'path', 'ip', 'referrer', 'user_agent']
                error_display = error_df[display_cols].sort_values('time', ascending=False).reset_index(drop=True)
                error_display.columns = ['Time', 'Status', 'Path', 'IP', 'Referrer', 'User Agent']
                st.dataframe(error_display, width='stretch')
            else:
                st.info("No errors found in logs")

        with tab4:
            st.header("Suspicious Activity Detection")
            error_stats = df.groupby('ip').agg(
                total_requests=('status', 'count'),
                error_requests=('status', lambda x: (x >= 400).sum())
            )
            error_stats['error_rate'] = error_stats['error_requests'] / error_stats['total_requests']
            high_error_ips = error_stats[(error_stats['error_rate'] > 0.5) & (error_stats['total_requests'] > 10)]
            high_error_ips = high_error_ips.sort_values('error_rate', ascending=False).head(10)
            high_error_ips['error_rate'] = (high_error_ips['error_rate'] * 100).round(1).astype(str) + '%'
            high_error_ips = high_error_ips.reset_index()
            high_error_ips.columns = ['IP Address', 'Total Requests', 'Error Requests', 'Error Rate']
            st.subheader("IPs with High Error Rate (>50%)")
            st.dataframe(high_error_ips, width='stretch')

            notfound_ips = df[df['status'] == 404]['ip'].value_counts().head(10).reset_index()
            notfound_ips.columns = ['IP Address', '404 Count']
            st.subheader("IPs with Most 404s")
            st.dataframe(notfound_ips, width='stretch')
            top_request_ips = df['ip'].value_counts().head(10).reset_index()
            top_request_ips.columns = ['IP Address', 'Request Count']
            st.subheader("Top Requesting IPs")
            st.dataframe(top_request_ips, width='stretch')

        with tab5:
            st.header("File Types Analysis")
            st.subheader("Top Requested File Extensions")
            top_ext = df['extension'].value_counts().head(10).reset_index()
            top_ext.columns = ['Extension', 'Count']
            top_ext['Extension'] = top_ext['Extension'].replace('', '[root]')
            st.dataframe(top_ext, width='stretch')

            st.subheader("Top Requested Files")
            top_files = df['path'].value_counts().head(10).reset_index()
            top_files.columns = ['File Path', 'Count']
            st.dataframe(top_files, width='stretch')

            st.subheader("File Extension Distribution (Bar Chart)")
            fig_bar = px.bar(top_ext, x='Extension', y='Count', title="Top Requested File Extensions")
            st.plotly_chart(fig_bar, width='stretch')

            st.subheader("File Extension Distribution (Pie Chart)")
            fig_pie = px.pie(top_ext, names='Extension', values='Count',
                             title="Top Requested File Extensions (Pie)")
            st.plotly_chart(fig_pie, width='stretch')

            st.markdown("""
                **Details:**
                - The table above shows the most frequently requested file extensions (e.g., html, php, js, css, jpg, png).
                - The bar and pie charts visualize the distribution of file types.
                - The "Top Requested Files" table shows the most accessed individual files/paths.
                """)

        with tab6:
            st.header("Bot & Crawler Detection")
            bot_keywords = [
                "bot", "spider", "crawl", "slurp", "baidu", "bingpreview", "duckduckbot", "yandex", "sogou",
                "exabot",
                "facebot", "ia_archiver", "mj12bot", "ahrefsbot", "semrushbot", "dotbot", "gigabot", "seznambot",
                "panscient",
                "applebot", "petalbot", "gptbot", "python-requests", "curl", "wget"
            ]
            df['is_bot'] = df['user_agent'].str.lower().str.contains('|'.join(bot_keywords), na=False)
            bots_df = df[df['is_bot']]
            if not bots_df.empty:
                st.subheader("Top Bots & Crawlers by Request Count")
                top_bots = bots_df['user_agent'].value_counts().head(10).reset_index()
                top_bots.columns = ['User Agent', 'Request Count']
                st.dataframe(top_bots, width='stretch')

                st.subheader("Bot/Crawler Activity by Path")
                bot_paths = bots_df['path'].value_counts().head(10).reset_index()
                bot_paths.columns = ['Path', 'Request Count']
                st.dataframe(bot_paths, width='stretch')

                st.subheader("Bot/Crawler Error Rate")
                bot_error_rate = (bots_df['status'] >= 400).mean()
                st.metric("Bot/Crawler Error Rate", f"{bot_error_rate:.1%}")

                st.subheader("All Bot/Crawler Requests (sample output)")
                sample_bot_data = bots_df[['time', 'ip', 'path', 'status', 'user_agent']].head(50)
                st.dataframe(sample_bot_data, width='stretch')

                csv_bot_data = bots_df[['time', 'ip', 'path', 'status', 'user_agent']].to_csv(index=False)
                st.download_button(
                    label="Download Full Bot/Crawler Data as CSV",
                    data=csv_bot_data,
                    file_name="bot_crawler_requests.csv",
                    mime="text/csv"
                )
                st.caption("Showing a sample of 50 rows above. Download for the full dataset.")
            else:
                st.info("No bots or crawlers detected in the logs.")

        with tab7:
            st.header("Advanced Security Analysis")

            st.subheader("Potential Brute Force Attacks")
            brute_force_suspects = detect_brute_force(df)
            if not brute_force_suspects.empty:
                st.dataframe(brute_force_suspects, width='stretch')
            else:
                st.info("No potential brute force attacks detected.")

            st.subheader("Potential SQL Injection Attempts")
            sql_injection_df = detect_sql_injection(df)
            if not sql_injection_df.empty:
                st.dataframe(sql_injection_df[['time', 'ip', 'path', 'referrer']], width='stretch')
            else:
                st.info("No potential SQL injection attempts detected.")

            st.subheader("Potential XSS Attacks")
            xss_df = detect_xss(df)
            if not xss_df.empty:
                st.dataframe(xss_df[['time', 'ip', 'path', 'referrer']], width='stretch')
            else:
                st.info("No potential XSS attacks detected.")

            st.subheader("AbuseIPDB Check")
            if st.button("Check High Error Rate IPs against AbuseIPDB"):
                if st.session_state['abuseipdb_api_key']:
                    with st.spinner("Checking IPs against AbuseIPDB..."):
                        abuse_reports = []
                        for ip in high_error_ips['IP Address']:
                            report = check_abuseipdb(ip, st.session_state['abuseipdb_api_key'])
                            if report:
                                abuse_reports.append(report)
                        if abuse_reports:
                            st.dataframe(abuse_reports, width='stretch')
                        else:
                            st.info("No abuse reports found for the high-error-rate IPs.")
                else:
                    st.warning("Please enter your AbuseIPDB API key in the sidebar.")

    with tab8:
        st.header("PHP Errors")
        if php_error_logs:
            php_df = pd.concat(php_error_logs, ignore_index=True)
            error_type_options = ["All", "Fatal Error (Critical)", "Warning", "Info"]
            error_type = st.selectbox("Show only...", error_type_options, key="php_error_type")
            if error_type != "All":
                filtered_df = php_df[php_df['type'] == error_type]
            else:
                filtered_df = php_df
            st.dataframe(filtered_df, width='stretch')
            st.download_button(
                label="Download PHP Error Log as CSV",
                data=filtered_df.to_csv(index=False),
                file_name="php_error_log.csv",
                mime="text/csv"
            )
        else:
            st.info("No PHP errors found.")

    with tab9:
        st.header("WordPress Analysis")
        if all_logs:
            # Web Shell Probe Detection (Priority - show first!)
            st.subheader("🚨 Web Shell & Backdoor Probe Attempts")
            shell_summary = get_webshell_summary(df)
            shell_probes = detect_webshell_probes(df)

            if shell_summary['total_attempts'] > 0:
                st.error(f"⚠️ ALERT: Detected {shell_summary['total_attempts']} web shell probe attempts from {shell_summary['unique_ips']} unique IPs!")

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Probe Attempts", f"{shell_summary['total_attempts']:,}")
                with col2:
                    st.metric("Unique Attacker IPs", shell_summary['unique_ips'])
                with col3:
                    st.metric("Shell Types Detected", shell_summary['unique_shells'])
                with col4:
                    st.metric("Most Targeted Shell", shell_summary['most_targeted'])

                st.markdown("""
                **What are Web Shell Probes?**
                - Attackers scanning for backdoors/shells from previous compromises
                - Common shells: ALFA, HOKI, WSO, c99, r57, b374k
                - 404 status or 403 = Good (shell not found)
                - 200 status = CRITICAL (shell may exist - investigate immediately!)
                """)

                # Show detailed probe attempts
                st.dataframe(shell_probes, width='stretch')

                # Download option
                st.download_button(
                    label="Download Web Shell Probe Data as CSV",
                    data=shell_probes.to_csv(index=False),
                    file_name="webshell_probes.csv",
                    mime="text/csv"
                )

                # Recommendations
                with st.expander("🛡️ Security Recommendations"):
                    st.markdown("""
                    ### Immediate Actions:
                    1. **Block the IPs listed above** - Add them to your firewall/WAF
                    2. **Check for 200 Status Codes** - If any probes returned 200, investigate immediately
                    3. **Scan for shells** - Run a file integrity check on your WordPress installation
                    4. **Review file permissions** - Ensure wp-content is not world-writable

                    ### Long-term Protection:
                    - Make sure Cerber is activated.
                    - Enable a Web Application Firewall (WAF)
                    - Keep WordPress core, plugins, and themes updated
                    - Use strong passwords and 2FA for all admin accounts
                    - Regular security audits and file integrity monitoring

                    ### Understanding the Threats:
                    - **ALFA Shell**: Full-featured PHP backdoor with file manager, SQL client, command execution
                    - **HOKI Shell**: Similar to ALFA, popular among attackers
                    - **WSO Shell**: "Web Shell by Orb" - one of the most common
                    - **c99/r57**: Classic shells, still widely used in scans
                    """)
            else:
                st.success("✅ No web shell probe attempts detected - your site looks clean!")
                st.info("This section monitors attempts to access known backdoors and web shells like ALFA, HOKI, WSO, c99, and others.")

            st.markdown("---")  # Separator

            wp_patterns = detect_wordpress_patterns(df)

            # Plugin Analysis
            st.subheader("Plugin Usage")
            if isinstance(wp_patterns['plugins'], pd.DataFrame) and not wp_patterns['plugins'].empty:
                st.dataframe(wp_patterns['plugins'].head(20), width='stretch')
                st.download_button(
                    label="Download Plugin Data as CSV",
                    data=wp_patterns['plugins'].to_csv(index=False),
                    file_name="wordpress_plugins.csv",
                    mime="text/csv"
                )
            else:
                st.info("No plugin requests detected in logs")

            # Theme Analysis
            st.subheader("Theme Usage")
            if isinstance(wp_patterns['themes'], pd.DataFrame) and not wp_patterns['themes'].empty:
                st.dataframe(wp_patterns['themes'].head(10), width='stretch')
            else:
                st.info("No theme requests detected in logs")

            # XML-RPC Abuse Detection
            st.subheader("XML-RPC Abuse Detection")
            xml_rpc_abuse = detect_xml_rpc_abuse(df, threshold=10)
            if not xml_rpc_abuse.empty:
                st.warning(f"⚠️ Detected {len(xml_rpc_abuse)} IPs with suspicious XML-RPC activity!")
                st.dataframe(xml_rpc_abuse, width='stretch')
                st.markdown("""
                **What is XML-RPC abuse?**
                - XML-RPC is a WordPress feature that can be exploited for brute force attacks
                - High volume of xmlrpc.php requests may indicate an attack
                - Consider disabling XML-RPC if not needed
                """)
            else:
                st.success("✅ No XML-RPC abuse detected")

            # wp-login Brute Force Detection
            st.subheader("wp-login.php Brute Force Attempts")
            wp_brute_force = detect_wp_login_brute_force(df, threshold=5)
            if not wp_brute_force.empty:
                st.warning(f"⚠️ Detected {len(wp_brute_force)} IPs with potential brute force attempts!")
                st.dataframe(wp_brute_force, width='stretch')
                st.markdown("""
                **Recommendations:**
                - Consider blocking these IPs
                - Implement rate limiting on wp-login.php and/or make sure a lockdown plugin is installed.
                - Use 2FA or login protection plugins
                """)
            else:
                st.success("✅ No brute force attempts detected")

            # WordPress Attack Patterns
            st.subheader("WordPress Attack Patterns")
            wp_attacks = detect_wordpress_attacks(df)
            if not wp_attacks.empty:
                st.error(f"🚨 Detected {len(wp_attacks)} types of WordPress attack patterns!")
                st.dataframe(wp_attacks, width='stretch')
                st.markdown("""
                **Common WordPress Attack Patterns Detected:**
                - Review these patterns and consider blocking suspicious IPs
                - Ensure WordPress core, plugins, and themes are up to date
                - Make sure WP Cerber is activated as well.
                """)
            else:
                st.success("✅ No WordPress attack patterns detected")

            # wp-admin Access
            st.subheader("wp-admin Access Patterns")
            if not wp_patterns['wp_admin_access'].empty:
                st.metric("Total wp-admin Requests", len(wp_patterns['wp_admin_access']))
                st.metric("Unique IPs Accessing wp-admin", wp_patterns['wp_admin_access']['ip'].nunique())

                # Show recent wp-admin access
                recent_admin = wp_patterns['wp_admin_access'].head(50)
                st.dataframe(recent_admin, width='stretch')
            else:
                st.info("No wp-admin access detected in logs")

            # wp-cron Analysis
            st.subheader("wp-cron.php Activity")
            wp_cron_stats = analyze_wp_cron(df)
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total wp-cron Requests", wp_cron_stats['total_requests'])
            with col2:
                st.metric("Unique IPs", wp_cron_stats['unique_ips'])
            with col3:
                st.metric("Avg Requests/Hour", f"{wp_cron_stats['avg_per_hour']:.2f}")

            if wp_cron_stats['total_requests'] > 0:
                st.markdown("""
                **About wp-cron.php:**
                - WordPress cron system for scheduled tasks
                - Triggered on page loads by default
                - High activity is normal for busy sites
                - Consider using system cron for better performance
                """)

            # Update/Maintenance Windows
            st.subheader("Update & Maintenance Activity")
            maintenance = detect_update_maintenance_windows(df)
            if not maintenance.empty:
                st.dataframe(maintenance, width='stretch')
            else:
                st.info("No update/maintenance activity detected")

        else:
            st.info("No logs available for WordPress analysis")

    with tab10:
        st.header("Performance Metrics")
        if all_logs:
            # Performance Summary
            st.subheader("Performance Summary")
            perf_summary = get_performance_summary(df)
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Requests", f"{perf_summary['total_requests']:,}")
                st.metric("Success Rate", f"{perf_summary['success_rate']:.2f}%")
            with col2:
                st.metric("Unique Visitors", f"{perf_summary['unique_visitors']:,}")
                st.metric("Client Error Rate (4xx)", f"{perf_summary['client_error_rate']:.2f}%")
            with col3:
                st.metric("Server Error Rate (5xx)", f"{perf_summary['server_error_rate']:.2f}%")

            # Traffic Patterns
            st.subheader("Traffic Patterns")
            traffic_patterns = analyze_traffic_patterns(df)
            if traffic_patterns:
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Peak Traffic Hour", f"{traffic_patterns['peak_hour']}:00")
                    st.metric("Peak Hour Requests", f"{traffic_patterns['peak_hour_requests']:,}")
                with col2:
                    st.metric("Lowest Traffic Hour", f"{traffic_patterns['low_hour']}:00")
                    st.metric("Low Hour Requests", f"{traffic_patterns['low_hour_requests']:,}")

                # Hourly traffic chart
                st.subheader("Requests by Hour of Day")
                fig_hourly = px.bar(traffic_patterns['hourly'], x='Hour_Label', y='Requests',
                                    title="Traffic Distribution by Hour",
                                    labels={'Hour_Label': 'Time of Day'})
                st.plotly_chart(fig_hourly, width='stretch')

                # Daily traffic chart
                st.subheader("Requests by Day of Week")
                fig_daily = px.bar(traffic_patterns['daily'], x='Day of Week', y='Requests',
                                   title="Traffic Distribution by Day of Week")
                st.plotly_chart(fig_daily, width='stretch')
            else:
                st.info("Unable to analyze traffic patterns - time data not available")

            # Endpoint Performance
            st.subheader("Endpoint Performance")
            endpoint_analysis = identify_slow_endpoints(df, top_n=20)

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Busiest Endpoints**")
                st.dataframe(endpoint_analysis['busiest_endpoints'], width='stretch')
            with col2:
                st.markdown("**Most Problematic Endpoints (by error rate)**")
                st.dataframe(endpoint_analysis['problematic_endpoints'], width='stretch')

            # Status Code Distribution
            st.subheader("Status Code Distribution")
            status_dist = analyze_status_code_distribution(df)
            st.dataframe(status_dist, width='stretch')

            # Visualize status codes
            fig_status = px.pie(status_dist, values='Count', names='Description',
                                title="Status Code Distribution")
            st.plotly_chart(fig_status, width='stretch')

            # HTTP Methods
            st.subheader("HTTP Method Analysis")
            method_stats = analyze_request_methods(df)
            st.dataframe(method_stats, width='stretch')

            # Cache Performance
            st.subheader("Cache Performance Analysis")
            cache_stats = analyze_cache_performance(df)
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Cache Hits (304)", f"{cache_stats['cache_hits_304']:,}")
            with col2:
                st.metric("Potential Cacheable (200)", f"{cache_stats['potential_cacheable_200']:,}")
            with col3:
                st.metric("Cache Hit Rate", f"{cache_stats['cache_hit_rate']:.2f}%")

            if 'static_cache_rate' in cache_stats:
                st.metric("Static File Cache Rate", f"{cache_stats['static_cache_rate']:.2f}%")
                st.markdown("""
                **Cache Performance Tips:**
                - Higher cache hit rates reduce server load
                - 304 responses indicate browser cache is working
                - Consider implementing CDN for static assets
                - Review cache headers for optimal performance
                """)

            # Bandwidth Analysis
            st.subheader("Bandwidth Usage by File Type")
            bandwidth = analyze_bandwidth_usage(df)
            st.dataframe(bandwidth.head(20), width='stretch')

            # Bandwidth visualization
            fig_bandwidth = px.bar(bandwidth.head(10), x='File Type', y='Estimated Total MB',
                                   title="Top 10 File Types by Bandwidth Usage")
            st.plotly_chart(fig_bandwidth, width='stretch')

            st.markdown("""
            **Note:** Bandwidth estimates are based on typical file sizes since actual bytes_sent
            may not be available in standard nginx logs. For accurate bandwidth data, enable
            $bytes_sent logging in your nginx configuration.
            """)

        else:
            st.info("No logs available for performance analysis")

else:
    st.info("Select site and env to begin analysis")
