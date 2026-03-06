from datetime import datetime


def is_failed_login(line):
    return "Failed password" in line

def extract_ip(line):
    parts = line.split()

    if "from" in parts:
        index = parts.index("from")
        return parts[index + 1]

    return None


def extract_log_time(line):
    try:
        parts = line.split()
        timestamp = " ".join(parts[:3])

        parsed = datetime.strptime(timestamp, "%b %d %H:%M:%S")

        # attach current year (syslog logs omit year)
        now = datetime.now()
        parsed = parsed.replace(year=now.year)

        return parsed

    except:
        return None


def format_alert(ip, attempts):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"[ALERT] {timestamp} | {ip} | {attempts} failed attempts"

