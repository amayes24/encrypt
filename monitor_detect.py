#!/usr/bin/env python3
import os
import sqlite3
import datetime
import math
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === Setup SQLite Logging ===
conn = sqlite3.connect('access_log.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,
    file_path TEXT,
    alert TEXT
)
''')
conn.commit()

# === Entropy Check ===
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def is_encrypted(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            entropy = calculate_entropy(data)
            return entropy > 7.5  # High entropy threshold
    except Exception:
        return False

# === Logging Function ===
def log_event(event_type, file_path, alert=None):
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO access_events (timestamp, event_type, file_path, alert)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, event_type, file_path, alert))
    conn.commit()

# === Watchdog Handler ===
class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if is_encrypted(file_path):
                log_event('MODIFIED', file_path, 'ALERT: Possible encryption attempt')
                print(f"[ALERT] Suspicious encryption detected: {file_path}")
            else:
                log_event('MODIFIED', file_path)

# === Start Monitoring ===
def start_monitoring(path_to_watch):
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    print(f"Monitoring started on: {path_to_watch}")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# === Run ===
if __name__ == "__main__":
    watch_path = "/home/kali/personal_1000"  # Change this to your target directory
    start_monitoring(watch_path)
