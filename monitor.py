import time
import threading
import queue
from collections import deque
from scapy.all import sniff, IP, TCP

from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.console import Console

from database import log_alert
from detection_rules import detect_port_scan

# A thread-safe queue to pass messages from the sniffing thread to the UI thread
update_queue = queue.Queue()

# --- Dashboard UI Elements ---
console = Console()
layout = Layout()

# Create main sections
layout.split(
    Layout(name="header", size=3),
    Layout(ratio=1, name="main"),
    Layout(size=3, name="footer"),
)

# Split the main section into a side panel and the alert log
layout["main"].split_row(Layout(name="side"), Layout(name="body", ratio=2))

# --- Sniffing Logic (runs in a background thread) ---
def sniffing_thread_func(interface=None):
    """The function that will be run in the background thread."""
    def packet_callback(packet):
        """This callback is now much simpler."""
        update_queue.put({"type": "packet_count", "count": 1})

        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            is_scan, scan_details = detect_port_scan(src_ip, dst_port)
            if is_scan:
                alert_msg = f"Port scan from [bold cyan]{src_ip}[/bold cyan] ({scan_details})"
                log_alert("Port Scan", src_ip, scan_details)
                update_queue.put({"type": "alert", "message": alert_msg})

    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        error_msg = f"Sniffing error: {e}"
        update_queue.put({"type": "alert", "message": f"[bold red]{error_msg}[/bold red]"})

def run_dashboard(interface=None):
    """Sets up and runs the live dashboard."""
    
    # Start the sniffing process in a separate thread
    sniffer_thread = threading.Thread(target=sniffing_thread_func, args=(interface,), daemon=True)
    sniffer_thread.start()

    # --- Live Dashboard State Variables ---
    total_packets = 0
    packets_per_second = 0
    last_check_time = time.time()
    packet_count_since_last_check = 0
    recent_alerts = deque(maxlen=15) # Store the last 15 alerts

    with Live(layout, screen=True, redirect_stderr=False, refresh_per_second=10) as live:
        try:
            while True:
                # --- Update state from the queue ---
                while not update_queue.empty():
                    item = update_queue.get()
                    if item["type"] == "packet_count":
                        total_packets += item["count"]
                        packet_count_since_last_check += item["count"]
                    elif item["type"] == "alert":
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        recent_alerts.appendleft(f"[{timestamp}] {item['message']}")

                # --- Calculate packets per second ---
                current_time = time.time()
                if current_time - last_check_time >= 1.0:
                    packets_per_second = packet_count_since_last_check / (current_time - last_check_time)
                    packet_count_since_last_check = 0
                    last_check_time = current_time

                # --- Update UI Panels ---
                header = Panel("[bold green]🛡️ Network Security Monitor - Live Dashboard[/bold green]", border_style="green")
                footer = Panel("Press [bold]Ctrl+C[/bold] to stop monitoring.", border_style="dim")

                stats_table = Table(show_header=False, box=None)
                stats_table.add_row("[bold]Packets/Sec[/bold]", f"{packets_per_second:.2f}")
                stats_table.add_row("[bold]Total Packets[/bold]", f"{total_packets:,}")
                stats_table.add_row("[bold]Alerts Found[/bold]", f"{len(list(recent_alerts)):,}")
                
                side_panel = Panel(stats_table, title="[bold]Live Statistics[/bold]", border_style="cyan")
                
                alert_log_content = "\n".join(recent_alerts)
                body_panel = Panel(alert_log_content, title="[bold]Recent Alerts[/bold]", border_style="red")

                # Update the main layout
                layout["header"].update(header)
                layout["footer"].update(footer)
                layout["side"].update(side_panel)
                layout["body"].update(body_panel)

                time.sleep(0.1) # Prevents high CPU usage

        except KeyboardInterrupt:
            print("\nStopping dashboard...")