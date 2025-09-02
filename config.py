# config.py

# --- General Settings ---
DATABASE_NAME = "alerts.db"

# --- Port Scan Detection Settings ---
# Time window in seconds to monitor for a scan
PORT_SCAN_TIME_WINDOW = 60
# Number of unique ports contacted to trigger an alert
PORT_SCAN_THRESHOLD = 15
