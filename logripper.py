import argparse
from datetime import datetime

from detector import BruteForceDetector
from parser import parse_static, parse_live


def logripper():


    # CLI argument parsing
    parser = argparse.ArgumentParser(description="SOC Log Analyzer")
    parser.add_argument(
                        "logfile",
                        help="Path to the log file"
    )

    parser.add_argument(
                        "-t",
                        "--threshold",
                        type=int,
                        default=5,
                        help="Number of failed attempts before alert"
    )

    parser.add_argument(
                        "-l",
                        "--live",
                        action="store_true",
                        help="Enable live monitoring mode"
    )

    parser.add_argument(
                        "--since",
                        help="Analyze logs since a specific time (e.g. '2026-03-01 10:00:00', '5h', '2w')",
                        default=None
)

    args = parser.parse_args()

    
    # HEADER OUTPUT
    print("================================================")
    print("SSH Brute-Force Log Analysis")
    print(f"Log File   : {args.logfile}")
    print(f"Threshold  : {args.threshold} attempts")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================")
    print()


    # Create detector
    detector = BruteForceDetector(args.threshold)


     # Select parser mode
    if args.live:
        parse_live(args.logfile, detector)
    else:
        parse_static(args.logfile, detector, args.since)


if __name__ == "__main__":
    logripper()
