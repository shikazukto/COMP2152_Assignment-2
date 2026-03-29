"""
Author: Rabin Kunnananickal Binu
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping port numbers to common service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter encapsulates the internal __target attribute,
    # preventing direct external access or accidental modification. The setter lets us
    # add validation logic (e.g., rejecting empty strings) in one place, keeping the
    # class interface clean and safe. Without this, any code could set self.__target
    # to any value, including invalid ones, with no protection.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool using super().__init__(target), which means
# it automatically gets the private __target attribute, the @property getter, and the
# @target.setter with its validation logic — without rewriting any of that code.
# For example, when you access scanner.target, it calls NetworkTool's @property getter.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, if the target machine is unreachable or the connection
        # times out, Python would raise an unhandled socket.error (or similar exception),
        # crashing the entire thread — and potentially the whole program. Since scan_port
        # runs inside threads, an unhandled exception in one thread could corrupt shared
        # state and produce no results at all. The try-except lets us catch errors
        # gracefully, print a message, and continue scanning other ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Each port scan waits up to 1 second for a response (the timeout), so scanning
    # 1024 ports sequentially could take over 17 minutes in the worst case. Threading
    # allows all ports to be scanned concurrently, reducing total scan time to roughly
    # the time of a single port scan. Without threads, the scanner would be impractically
    # slow for any real-world use.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            port, status, service = result
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        for row in rows:
            _, target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


# ── Main Program ──────────────────────────────────────────────────────────────
if __name__ == "__main__":

    # Get target IP
    target_ip = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target_ip == "":
        target_ip = "127.0.0.1"

    # Get start port
    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter start port (1–1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port
    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter end port (1–1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Run the scanner
    scanner = PortScanner(target_ip)
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target_ip} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target_ip, open_ports)

    see_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if see_history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# I would add an OS fingerprinting feature that uses a list comprehension to filter
# scan results for a specific set of ports that are characteristic of particular
# operating systems (e.g., port 3389 for Windows RDP, port 548 for macOS AFP).
# The feature would use a list comprehension like:
#   windows_indicators = [p for p, s, _ in open_ports if p in [135, 139, 445, 3389] and s == "Open"]
# to detect likely OS type from the open port pattern, then print a "Likely OS" guess.
# Diagram: See diagram_101201301.png in the repository root