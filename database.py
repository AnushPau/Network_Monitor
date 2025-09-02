import sqlite3
from config import DATABASE_NAME

def init_db():
    """Initializes the database and creates the 'alerts' table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_alert(alert_type, source_ip, details):
    """Logs a new security alert to the database."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (alert_type, source_ip, details) VALUES (?, ?, ?)",
        (alert_type, source_ip, details)
    )
    conn.commit()
    conn.close()

def get_summary():
    """Returns a summary of alerts grouped by type and IP."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT alert_type, source_ip, COUNT(*) as count
        FROM alerts
        GROUP BY alert_type, source_ip
        ORDER BY count DESC
    ''')
    results = cursor.fetchall()
    conn.close()
    return results

def query_alerts(ip=None, alert_type=None):
    """Queries alerts with optional filters for IP and alert type."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    query = "SELECT timestamp, alert_type, source_ip, details FROM alerts"
    filters = []
    params = []

    if ip:
        filters.append("source_ip = ?")
        params.append(ip)
    if alert_type:
        filters.append("alert_type = ?")
        params.append(alert_type)

    if filters:
        query += " WHERE " + " AND ".join(filters)
    
    query += " ORDER BY timestamp DESC"
    
    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()
    return results