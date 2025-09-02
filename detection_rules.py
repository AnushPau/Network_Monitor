import time
from config import PORT_SCAN_TIME_WINDOW, PORT_SCAN_THRESHOLD

# In-memory storage for tracking potential port scans
ip_scan_tracker = {}

def detect_port_scan(src_ip, dst_port):
    """Analyzes packet data in-memory to detect a port scan."""
    current_time = time.time()

    # Clean up expired entries from our tracker
    expired_ips = [ip for ip, data in ip_scan_tracker.items() if current_time - data['timestamp'] > PORT_SCAN_TIME_WINDOW]
    for ip in expired_ips:
        del ip_scan_tracker[ip]

    # Initialize tracker for new IP
    if src_ip not in ip_scan_tracker:
        ip_scan_tracker[src_ip] = {'timestamp': current_time, 'ports': set()}

    # Add the port to the set for this IP and update the timestamp
    ip_scan_tracker[src_ip]['ports'].add(dst_port)
    ip_scan_tracker[src_ip]['timestamp'] = current_time

    # Check if the threshold has been crossed
    if len(ip_scan_tracker[src_ip]['ports']) > PORT_SCAN_THRESHOLD:
        targeted_ports = sorted(list(ip_scan_tracker[src_ip]['ports']))
        # Reset after detection to prevent repeated alerts for the same scan
        del ip_scan_tracker[src_ip]
        return True, f"Targeted {len(targeted_ports)} ports. Examples: {targeted_ports[:5]}"

    return False, None