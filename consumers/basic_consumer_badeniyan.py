"""
basic_consumer_yourname.py

Reads a log file in real time and detects special conditions.
"""

import os
import time
import re
from utils.utils_logger import logger, get_log_file_path

def process_message(log_file) -> None:
    """
    Read a log file and process each message.

    Args:
        log_file (str): The path to the log file to read.
    """
    with open(log_file, "r") as file:
        file.seek(0, os.SEEK_END)
        print("Consumer is ready and waiting for new log messages...")

        # Define patterns to detect specific alerts
        alert_patterns = [
            (re.compile(r"⚡ High CPU usage detected!"), "ALERT: CPU usage spike detected!"),
            (re.compile(r"❗ Warning: Unusual activity detected!"), "ALERT: Security threat detected!")
        ]

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)  # Wait for a new log entry
                continue

            message = line.strip()
            print(f"Consumed log message: {message}")

            # Check for alert conditions
            for pattern, alert_message in alert_patterns:
                if pattern.search(message):
                    print(alert_message)
                    logger.warning(alert_message)

def main() -> None:
    """Main entry point."""
    logger.info("START...")

    log_file_path = get_log_file_path()
    logger.info(f"Reading file located at {log_file_path}.")

    try:
        process_message(log_file_path)
    except KeyboardInterrupt:
        print("User stopped the process.")

    logger.info("END.....")

if __name__ == "__main__":
    main()
