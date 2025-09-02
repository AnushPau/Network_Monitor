🛡️ Python Network Security Monitor
A modular, multi-threaded network security monitor for real-time packet analysis and threat detection. The system leverages Scapy for packet capture and features a stateful detection engine for identifying anomalies like port scans. Alerts are persisted to a local SQLite database and can be queried via a command-line interface. A real-time TUI dashboard provides live operational metrics.

Core Features
Multi-Threaded Architecture: Decouples packet sniffing from the UI to ensure non-blocking, high-performance packet processing.

Stateful Detection Engine: In-memory tracking of connection states and port activity to identify reconnaissance patterns (e.g., port scans) over configurable time windows.

Real-time TUI Dashboard: A terminal-based user interface built with rich for live visualization of packet throughput and a deque of recent security alerts.

SQLite Alert Persistence: All generated alerts are logged to a structured SQLite database for offline analysis and querying.

Modular & Extensible Design: The detection logic, database interaction, and UI are separated into distinct modules, allowing for easy addition of new threat detection rules.

System Architecture
The monitor operates on a two-thread model to maintain responsiveness:

Sniffing Thread (monitor.py): A background daemon thread that runs a Scapy sniff() loop. Each captured packet is passed to the detection_rules module. To prevent blocking the main thread, any generated alerts or metric updates are pushed into a thread-safe queue.Queue.

Main/UI Thread (monitor.py): This thread is responsible for rendering the rich Live dashboard. It continuously reads from the queue, updates the UI components with new statistics and alerts, and manages the application state.

This design ensures that packet capture is not interrupted by UI rendering, and the UI remains fluid even under moderate network load.

Setup and Installation
Clone the repository:

git clone [https://github.com/AnushPau/Network_Monitor.git](https://github.com/AnushPau/Network_Monitor.git)
cd Network_Monitor

Install dependencies:
It is recommended to use a virtual environment.

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

Platform-Specific Dependencies:

Windows: Requires Npcap installed in "WinPcap API-compatible Mode."

Linux/macOS: Requires root privileges (sudo) for packet sniffing.

Usage (CLI)
The application is controlled via main.py. Execution requires elevated privileges.

Launch the Real-time Dashboard:

# Specify an interface if auto-detection fails
sudo python main.py start --interface eth0

Query the Alert Database:
The query commands access the alerts.db file directly.

# Get an aggregated summary of all alerts
python main.py summary

# Filter alerts by source IP or type
python main.py query --ip "192.168.1.10"
python main.py query --type "Port Scan"

Extensibility
To add a new detection rule (e.g., for SQL injection attempts):

detection_rules.py: Add a new function, detect_sql_injection(packet), with its own state-tracking logic.

monitor.py: Import and call the new function from within the packet_callback.

database.py: Update the log_alert function if new alert details are required.