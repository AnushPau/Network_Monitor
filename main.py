import argparse
from database import init_db, get_summary, query_alerts
from monitor import run_dashboard

def main():
    # Ensure the database exists before doing anything
    init_db()

    parser = argparse.ArgumentParser(description="A simple network security monitoring tool.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- 'start' command ---
    start_parser = subparsers.add_parser("start", help="Start the network monitor dashboard.")
    start_parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., 'Wi-Fi', 'eth0').")

    # --- 'summary' command ---
    summary_parser = subparsers.add_parser("summary", help="Show a summary of all detected alerts.")

    # --- 'query' command ---
    query_parser = subparsers.add_parser("query", help="Query the alert log with filters.")
    query_parser.add_argument("--ip", help="Filter alerts by source IP address.")
    query_parser.add_argument("--type", help="Filter alerts by type (e.g., 'Port Scan').")

    args = parser.parse_args()

    if args.command == "start":
        try:
            run_dashboard(interface=args.interface)
        except Exception as e:
            print(f"Failed to start dashboard: {e}")
            print("Please ensure you are running with administrator/root privileges.")

    elif args.command == "summary":
        results = get_summary()
        if not results:
            print("No alerts found in the database.")
            return
        print(f"{'Alert Type':<15} | {'Source IP':<18} | {'Count'}")
        print("-" * 45)
        for row in results:
            print(f"{row[0]:<15} | {row[1]:<18} | {row[2]}")
    elif args.command == "query":
        results = query_alerts(ip=args.ip, alert_type=args.type)
        if not results:
            print("No alerts found matching your criteria.")
            return
        print(f"{'Timestamp':<22} | {'Alert Type':<15} | {'Source IP':<18} | {'Details'}")
        print("-" * 80)
        for row in results:
            print(f"{row[0]:<22} | {row[1]:<15} | {row[2]:<18} | {row[3]}")

if __name__ == "__main__":
    main()