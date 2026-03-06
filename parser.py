from datetime import datetime, timedelta
from utils import extract_ip, extract_log_time
import time


def parse_since(since):
    now = datetime.now()

    if since is None:
        return None

    # relative hours
    if since.endswith("h"):
        return now - timedelta(hours=int(since[:-1]))

    # relative weeks
    if since.endswith("w"):
        return now - timedelta(weeks=int(since[:-1]))

    # try full datetime first
    try:
        return datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    # try syslog style
    try:
        parsed = datetime.strptime(since, "%b %d %H:%M:%S")
        return parsed.replace(year=now.year)
    except ValueError:
        raise ValueError(
            "Invalid --since format. Use 'YYYY-MM-DD HH:MM:SS', 'Jun 10 10:01:00', '5h', or '2w'."
        )


def parse_static(logfile, detector, since=None):

    print("Reading log file...\n")
    start_time = parse_since(since)
    attempts = {}

    try:
        with open(logfile, "r") as f:

            for line in f:

                log_time = extract_log_time(line)

                if start_time and log_time and log_time < start_time:
                    continue

                ip = extract_ip(line)

                if ip:
                    attempts[ip] = attempts.get(ip, 0) + 1

    except FileNotFoundError:
        print(f"Error: log file '{logfile}' not found")
        return

    found = False

    for ip, count in attempts.items():
        if count >= detector.threshold:
            print(f"[ALERT] {ip} | {count} failed attempts")
            found = True

    if not found:
        print("No brute-force attempts detected.")

    print("\nAnalysis Complete.")


def parse_live(logfile, detector):

    print(f"Monitoring {logfile}...\n")
    print("Press CTRL+C to stop.\n")

    try:
        with open(logfile, "r") as f:

            f.seek(0, 2)

            while True:

                line = f.readline()

                if not line:
                    time.sleep(0.5)
                    continue

                while line:

                    alert = detector.process_line(line)

                    if alert:
                        print(alert)
                    line = f.readline()


    except FileNotFoundError:
        print(f"Error: log file '{logfile}' not found")

    except KeyboardInterrupt:
        print("\n\nLive monitoring stopped.")
        print("Exiting logripper.")