#!/
#!/usr/bin/env python3
"""
monitor_detect.py
Ransomware-oriented file integrity monitoring with rule-based detection, per-process scoring,
and mitigation (SIGSTOP/SIGKILL). Logs structured events to SQLite.
"""

import os
import sqlite3
import datetime
import math
import subprocess
import signal
import smtplib
import shutil
import threading
import time
import logging
import pwd
from collections import defaultdict, deque
from email.message import EmailMessage
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === Configuration ===
WATCH_PATH = "/home/kali/personal_1000"

ADMIN_EMAIL = "kali@localhost"
USE_LOCAL_SMTP = True
SMTP_SERVER = "localhost"
SMTP_PORT = 1025
SMTP_USER = ""
SMTP_PASS = ""

# Add substrings of commands or absolute paths to ignore (whitelist benign actors)
WHITELIST_CMDS = [
    "vim", "nano", "code", "gedit",
    "systemd", "rsyslogd", "sshd",
    "backup", "rsync", "duplicity", "restic",
    "/usr/bin/gpg", "openssl"
]

# Mitigation action: "stop" for SIGSTOP, "kill" for SIGKILL
SUSPEND_ACTION = "kill"

# Entropy read limit and threshold
ENTROPY_READ_LIMIT = 1024 * 1024  # up to 1MB
ENTROPY_THRESHOLD = 7.5
SIZE_FLOOR_BYTES = 32 * 1024  # 32KB floor to avoid tiny binary blobs

# Windowed rule evaluation
WINDOW_SECONDS = 60
THRESHOLD_SCORE = 10
RULE_SCORE = {
    "R1": 3,  # Entropy spike after write (>=5 high-entropy mods)
    "R2": 4,  # High modification rate (>=50 mods)
    "R3": 3,  # Write→rename chains (>=10 renames)
    "R4": 3,  # Widespread extension changes (>=20)
    "R5": 3,  # Delete-after-write pattern (>=15 deletes)
    "R6": 2,  # Non-whitelisted actor
}

EXCLUDE_DIR_SUBSTR = [
    "/tmp/", "/var/tmp/", "/run/", "/var/cache/"
]

# === Logging ===
logging.basicConfig(
    filename="monitor_detect.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# === Setup SQLite Logging ===
conn = sqlite3.connect('access_log.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,        -- CREATED / MODIFIED / MOVED / DELETED
    file_path TEXT,
    file_ext TEXT,
    file_entropy REAL,      -- NULL if unreadable/too small
    file_size INTEGER,      -- NULL if unreadable
    proc_pid INTEGER,       -- NULL if unknown
    proc_cmd TEXT,          -- trimmed command line
    user TEXT,              -- linux account name
    alert TEXT
)
''')
conn.commit()

# === Entropy Check ===
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def safe_file_stats(file_path: str):
    # Returns (size, ext, entropy or None)
    try:
        st = os.stat(file_path)
        size = st.st_size
    except Exception:
        size = None
    ext = os.path.splitext(file_path)[1].lower()
    entropy = None
    try:
        if size and size > 0:
            read_len = min(size, ENTROPY_READ_LIMIT)
            with open(file_path, 'rb') as f:
                data = f.read(read_len)
            if read_len >= SIZE_FLOOR_BYTES:
                entropy = calculate_entropy(data)
    except Exception:
        entropy = None
    return size, ext, entropy

def is_high_entropy_write(entropy: float, size: int) -> bool:
    return (entropy is not None and size is not None and size >= SIZE_FLOOR_BYTES and entropy >= ENTROPY_THRESHOLD)

# Extra helper (optional): direct entropy probe on a path
def is_encrypted(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            data = f.read(ENTROPY_READ_LIMIT)
            entropy = calculate_entropy(data)
            logging.debug(f"Entropy for {file_path}: {entropy:.3f}")
            return entropy > ENTROPY_THRESHOLD
    except Exception as e:
        logging.debug(f"Could not read {file_path} for entropy: {e}")
        return False

# === Helpers ===
def whoami() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return "unknown"

def get_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().replace(b'\x00', b' ').strip()
            return raw.decode(errors="ignore")
    except Exception:
        return ""

def get_proc_for_path(file_path: str):
    # Use lsof with field formatting to get PID and command quickly
    try:
        out = subprocess.check_output(['lsof', '-Fpcn', file_path], stderr=subprocess.DEVNULL).decode()
        pid, cmd = None, None
        for line in out.splitlines():
            if line.startswith('p') and pid is None:
                try:
                    pid = int(line[1:])
                except Exception:
                    pid = None
            elif line.startswith('c') and cmd is None:
                cmd = line[1:]
            if pid is not None and cmd is not None:
                break
        return pid, cmd
    except subprocess.CalledProcessError:
        return None, None
    except FileNotFoundError:
        logging.error("lsof not installed; install lsof to enable process attribution")
        return None, None
    except Exception as e:
        logging.exception(f"Unexpected error in get_proc_for_path: {e}")
        return None, None

def path_excluded(file_path: str) -> bool:
    fp = file_path.lower()
    for sub in EXCLUDE_DIR_SUBSTR:
        if sub in fp:
            return True
    return False

# === Logging Function ===
def log_event(event_type: str, file_path: str, alert: str = None, pid: int = None, cmd: str = None, entropy: float = None, size: int = None):
    timestamp = datetime.datetime.now().isoformat()
    user = whoami()
    file_ext = os.path.splitext(file_path)[1].lower()
    try:
        cursor.execute('''
            INSERT INTO access_events (timestamp, event_type, file_path, file_ext, file_entropy, file_size, proc_pid, proc_cmd, user, alert)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, event_type, file_path, file_ext, entropy, size, pid, cmd, user, alert))
        conn.commit()
    except Exception as e:
        logging.exception(f"SQLite insert failed: {e}")
    logging.info(f"{event_type} {file_path} pid={pid} {alert or ''}")

# === Mitigation ===
def kill_process_using_pid(pid: int, action: str = "stop") -> bool:
    if pid is None:
        return False
    if pid == os.getpid():
        return False
    cmdline = get_cmdline(pid)
    if any(w in cmdline for w in WHITELIST_CMDS):
        logging.info(f"Skipping whitelisted process {pid} ({cmdline})")
        return False
    sig = signal.SIGSTOP if action == "stop" else signal.SIGKILL
    try:
        os.kill(pid, sig)
        logging.info(f"Signaled {pid} ({cmdline}) with {sig}")
        return True
    except PermissionError:
        logging.error(f"Permission denied signaling pid {pid}")
    except ProcessLookupError:
        logging.warning(f"Process {pid} disappeared before signaling")
    except Exception as e:
        logging.exception(f"Unexpected error signaling pid {pid}: {e}")
    return False

# Extra helper (optional): kill processes holding a file directly
def kill_process_using_file(file_path: str, action: str = "stop") -> list:
    suspended = []
    try:
        output = subprocess.check_output(['lsof', '-t', file_path], stderr=subprocess.DEVNULL).decode().strip()
        if not output:
            return suspended
        for line in output.splitlines():
            try:
                pid = int(line.strip())
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            cmd = get_cmdline(pid)
            if any(w in cmd for w in WHITELIST_CMDS):
                logging.info(f"Skipping whitelisted process {pid} ({cmd})")
                continue
            sig = signal.SIGSTOP if action == "stop" else signal.SIGKILL
            try:
                os.kill(pid, sig)
                suspended.append(pid)
                logging.info(f"Signaled {pid} ({cmd}) with {sig}")
            except PermissionError:
                logging.error(f"Permission denied signaling pid {pid}")
            except ProcessLookupError:
                logging.warning(f"Process {pid} disappeared before signaling")
    except subprocess.CalledProcessError:
        logging.debug("lsof returned no processes for file")
    except FileNotFoundError:
        logging.error("lsof not installed; install lsof to enable process lookup")
    except Exception as e:
        logging.exception(f"Unexpected error in kill_process_using_file: {e}")
    return suspended

# === Notification ===
def send_notification(subject_detail: str, pids: list, triggered_rules: list = None, score: int = 0):
    title = "Security Alert"
    rules_str = ", ".join(triggered_rules or [])
    body = (
        f"Possible ransomware activity: {subject_detail}\n"
        f"Mitigated PIDs: {pids or 'none'}\n"
        f"Rules: {rules_str or 'n/a'} | Score: {score}"
    )
    # Desktop notification if available
    if shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", title, body], check=False)
            logging.info("Desktop notification sent")
            return
        except Exception as e:
            logging.error(f"notify-send failed: {e}")
    # Fallback to email
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = 'Security Alert: Possible Ransomware Activity'
        msg['From'] = f"monitor@{os.uname().nodename}"
        msg['To'] = ADMIN_EMAIL
        if USE_LOCAL_SMTP:
            with smtplib.SMTP('localhost') as server:
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
        logging.info("Email notification sent")
    except Exception as e:
        logging.exception(f"Failed to send email notification: {e}")

# === Rule Engine (sliding window, per PID) ===
pid_events = defaultdict(lambda: deque(maxlen=10000))

def score_and_mitigate(pid: int):
    now = time.time()
    dq = pid_events[pid]
    # Keep only recent events
    while dq and now - dq[0]["t"] > WINDOW_SECONDS:
        dq.popleft()

    # Aggregate by type
    mods = [e for e in dq if e["type"] == "MODIFIED" and not path_excluded(e["path"])]
    renames = [e for e in dq if e["type"] == "MOVED" and not path_excluded(e["path"])]
    deletes = [e for e in dq if e["type"] == "DELETED" and not path_excluded(e["path"])]

    entropy_mods = [e for e in mods if is_high_entropy_write(e.get("entropy"), e.get("size"))]
    ext_changes = [e for e in renames if e.get("to_ext") and e.get("from_ext") != e.get("to_ext")]

    score = 0
    triggered = []

    if len(entropy_mods) >= 5:
        score += RULE_SCORE["R1"]; triggered.append("R1")
    if len(mods) >= 50:
        score += RULE_SCORE["R2"]; triggered.append("R2")
    if len(renames) >= 10:
        score += RULE_SCORE["R3"]; triggered.append("R3")
    if len(ext_changes) >= 20:
        score += RULE_SCORE["R4"]; triggered.append("R4")
    if len(deletes) >= 15:
        score += RULE_SCORE["R5"]; triggered.append("R5")

    cmdline = dq[-1].get("cmd", "") if dq else ""
    if not any(w in cmdline for w in WHITELIST_CMDS):
        score += RULE_SCORE["R6"]; triggered.append("R6")

    if score >= THRESHOLD_SCORE:
        logging.warning(f"Ransomware suspicion score={score} pid={pid} cmd={cmdline} rules={triggered}")
        pids_mitigated = []
        if os.geteuid() != 0:
            logging.warning("Not running as root; mitigation (SIGSTOP/SIGKILL) may fail.")
        if kill_process_using_pid(pid, action=SUSPEND_ACTION):
            pids_mitigated.append(pid)
        send_notification("bulk-change in watch window", pids_mitigated, triggered_rules=triggered, score=score)

# === Watchdog Handler ===
class MonitorHandler(FileSystemEventHandler):
    def _record_and_score(self, etype: str, fp: str, src: str = None, dst: str = None):
        if etype == "MOVED":
            # For moves, compute from/to stats separately
            _, from_ext, _ = safe_file_stats(src) if src else (None, None, None)
            size, to_ext, entropy = safe_file_stats(dst) if dst else (None, None, None)
            pid, cmd = get_proc_for_path(dst or fp)
            log_event('MOVED', dst or fp, pid=pid, cmd=cmd, entropy=entropy, size=size)
            if pid:
                pid_events[pid].append({
                    "t": time.time(), "type": "MOVED",
                    "path": dst or fp, "cmd": cmd,
                    "size": size, "entropy": entropy,
                    "from_ext": from_ext, "to_ext": to_ext
                })
                score_and_mitigate(pid)
            return

        # CREATED / MODIFIED / DELETED: try to attribute process and collect stats
        pid, cmd = get_proc_for_path(fp)
        size, ext, entropy = safe_file_stats(fp) if etype != "DELETED" else (None, os.path.splitext(fp)[1].lower(), None)
        log_event(etype, fp, pid=pid, cmd=cmd, entropy=entropy, size=size)

        if pid:
            event = {
                "t": time.time(),
                "type": etype,
                "path": fp,
                "cmd": cmd,
                "size": size,
                "entropy": entropy,
                "ext": ext
            }
            pid_events[pid].append(event)

            # Immediate alert if a single high-entropy write is detected
            if etype == "MODIFIED" and is_high_entropy_write(entropy, size):
                send_notification("High-entropy write detected", [pid],
                                  triggered_rules=["R1"], score=RULE_SCORE["R1"])
                kill_process_using_pid(pid, action=SUSPEND_ACTION)

            # Score on writes only to reduce overhead
            if etype in ("MODIFIED", "MOVED", "DELETED", "CREATED"):
                score_and_mitigate(pid)

    def on_created(self, event):
        if event.is_directory:
            return
        self._record_and_score("CREATED", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._record_and_score("MODIFIED", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._record_and_score("MOVED", event.dest_path, src=event.src_path, dst=event.dest_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._record_and_score("DELETED", event.src_path)

# === Start Monitoring ===
def start_monitoring(path_to_watch: str):
    if not os.path.exists(path_to_watch):
        os.makedirs(path_to_watch, exist_ok=True)
        logging.info(f"Created missing watch directory: {path_to_watch}")
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    print(f"Monitoring started on: {path_to_watch}")
    logging.info(f"Monitoring started on: {path_to_watch}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# === Run ===
if __name__ == "__main__":
    start_monitoring(WATCH_PATH)
