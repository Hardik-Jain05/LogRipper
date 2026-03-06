from utils import is_failed_login, extract_ip, format_alert, extract_log_time
from collections import deque
from datetime import datetime

class BruteForceDetector:

    def __init__(self, threshold=5):

        self.threshold = threshold

        # attempt counter
        self.ip_attempts = {}

        # escalation tracking
        self.next_alert = {}

        # time-window rule
        self.window_threshold = 10
        self.time_window = 60
        self.ip_windows = {}

        # surge detection
        self.alert_times = deque()
    
    def process_line(self, line):
        
        # Step 1: check if the line is a failed login
        if not is_failed_login(line):
            return None
        
        # Step 2: extract the IP
        ip = extract_ip(line)
        if not ip:
            return None
        
        # Step 3: update attempt counter
        self.ip_attempts[ip] = self.ip_attempts.get(ip, 0) + 1
        count = self.ip_attempts[ip]


        timestamp = extract_log_time(line)
        if not timestamp:
            timestamp = datetime.now()


        # -----------------------
        # progressive escalation
        # -----------------------
        if ip not in self.next_alert:
            self.next_alert[ip] = self.threshold

        alert_message = None

        if count >= self.next_alert[ip]:
            alert_message = format_alert(ip, count)
            self.next_alert[ip] *= 2

        # -----------------------
        # time window detection
        # -----------------------
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()

        window = self.ip_windows[ip]
        window.append(timestamp)

        while window and (timestamp - window[0]).seconds > self.time_window:
            window.popleft()

        if len(window) >= self.window_threshold:

            alert_message = (
                f"[ALERT] {timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{ip} | {len(window)} attempts within {self.time_window}s"
            )

            window.clear()

        # -----------------------
        # surge detection
        # -----------------------
        if alert_message:

            now = datetime.now()
            self.alert_times.append(now)

            while self.alert_times and (now - self.alert_times[0]).seconds > 10:
                self.alert_times.popleft()

            if len(self.alert_times) >= 2:
                print("[WARNING] High-volume brute force detected")

            return alert_message

        return None
    