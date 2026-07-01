import streamlit as st
import pandas as pd
import re
from datetime import datetime

st.set_page_config(page_title="Log Analytics Dashboard", layout="wide")


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+[^"]*"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
)

def parse_line(line):
    if isinstance(line, bytes):
        line = line.decode('utf-8', errors='ignore')
        
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
        
    row = match.groupdict()
    
    
    try:
        ts_clean = row['timestamp'].split(' ')[0]
        dt = datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")
        row['date'] = dt.date()
        row['time'] = dt.time()
    except ValueError:
        row['date'] = None
        row['time'] = None
        
    return row

def load_logs(file_lines):
    rows = []
    for line in file_lines:
        parsed = parse_line(line)
        if parsed:
            rows.append(parsed)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df['status'] = df['status'].astype(int)
    df['date'] = pd.to_datetime(df['date']).dt.date
    return df


# --- UI Layout ---
st.title("ðŸŒ Webserver Log Dashboard")
st.write("Upload Nginx/Apache log files to filter traffic and analyze access hits.")

log_file = st.sidebar.file_uploader("Upload Log File (.log, .txt)", type=["log", "txt"])

if not log_file:
    st.info("Please upload a log file from the sidebar to get started.")
    st.markdown("### Example Format:")
    st.code('10.50.81.46 - - [29/Jun/2026:12:02:38 +0500] "POST /user/Ajax/HeaderAjaxResponse HTTP/1.1" 200 2218')
else:
    df = load_logs(log_file.readlines())

    if df.empty:
        st.error("Couldn't parse any logs. Check if the file format matches standard webserver configurations.")
    else:
        # Sidebar setup
        st.sidebar.header("Filters")

        min_d, max_d = df['date'].min(), df['date'].max()
        start_date = st.sidebar.date_input("Start Date", min_d, min_value=min_d, max_value=max_d)
        end_date = st.sidebar.date_input("End Date", max_d, min_value=min_d, max_value=max_d)

        methods = df['method'].unique().tolist()
        selected_methods = st.sidebar.multiselect("HTTP Method", methods, default=methods)

        statuses = sorted(df['status'].unique().tolist())
        selected_status = st.sidebar.multiselect("Status Code", statuses, default=statuses)

        search_url = st.sidebar.text_input("Search URL Keyword", "")

        # Apply filtering
        filtered = df[
            (df['date'] >= start_date) &
            (df['date'] <= end_date) &
            (df['method'].isin(selected_methods)) &
            (df['status'].isin(selected_status))
        ]

        if search_url:
            filtered = filtered[filtered['url'].str.contains(search_url, case=False, na=False)]

        
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Hits", len(filtered))
        m2.metric("Unique IPs", filtered['ip'].nunique() if not filtered.empty else 0)
        m3.metric("Unique URLs", filtered['url'].nunique() if not filtered.empty else 0)

        
        tab1, tab2 = st.tabs(["Log Data", "IP & URL Breakdown"])

        with tab1:
            st.subheader("Parsed Log Entries")
            cols_to_show = ['ip', 'date', 'time', 'method', 'url', 'status', 'bytes']
            st.dataframe(filtered[cols_to_show], use_container_width=True)

        with tab2:
            st.subheader("Traffic Breakdown by IP and URL")

            if not filtered.empty:
                counts = (
                    filtered.groupby(['ip', 'url'])
                    .size()
                    .reset_index(name='Hits')
                    .sort_values(by='Hits', ascending=False)
                )

                
                unique_ips = ["All"] + list(counts['ip'].unique())
                filter_ip = st.selectbox("Isolate Specific IP:", unique_ips)

                if filter_ip != "All":
                    counts = counts[counts['ip'] == filter_ip]

                st.dataframe(counts, use_container_width=True)
            else:
                st.write("No entries match the selected filters.")