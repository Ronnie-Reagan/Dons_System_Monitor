import psutil
import tkinter as tk
from tkinter import ttk
import threading
import time
import platform
import shutil
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import socketserver
import json
import argparse
import copy
import socket

# ==============================
# Path handling for EXE builds
# ==============================

def get_base_dir() -> str:
    """
    Return the directory that should hold the config/log files.

    - When frozen by PyInstaller: folder containing the .exe
    - When running from source: folder containing this script
    """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()

CONFIG_FILE_NAME = "sysmon.config.json"
CONFIG_PATH = os.path.join(BASE_DIR, CONFIG_FILE_NAME)
LOG_FILE_NAME = "system_monitor.log"
LOG_FILE = os.path.join(BASE_DIR, LOG_FILE_NAME)

# ==============================
# Configuration (defaults)
# These can be overridden by config file
# ==============================

# Host / collector behaviour
UPDATE_INTERVAL_SEC = 2.0

HIGH_RAM_THRESHOLD = 95        # % (total utilization)
HIGH_CPU_THRESHOLD = 70        # % (per process)
HIGH_RAM_USAGE = 30            # % (per process)

MEMORY_TREND_LENGTH = 20       # samples
MEMORY_LEAK_MIN_INCREASE = 5.0 # percentage points over window

MAX_TRACKED_PROCS = 300        # cap number of PIDs tracked for trends
MAX_PROBLEM_ENTRIES = 500      # cap number of problems in snapshot

SYSMAIN_COOLDOWN_SEC = 300     # don't spam Stop-Service

REMOTE_BIND_ADDR = "0.0.0.0"
REMOTE_PORT = 34255
REMOTE_PASSWORD = ""           # will be overwritten by config

# Viewer / remote client behaviour
VIEWER_SERVER_IP = "127.0.0.1"
VIEWER_SERVER_PORT = 34255
VIEWER_PASSWORD = "changeme"
VIEWER_REFRESH_MS = 1000
VIEWER_DEFAULT = False         # if true in config, default mode='viewer'

# This will hold full config dict after loading
CONFIG = {}

# ==============================
# Logging
# ==============================

logger = logging.getLogger("sysmon")
logger.setLevel(logging.INFO)

def _create_log_handler(path: str):
    try:
        handler = RotatingFileHandler(
            path, maxBytes=2 * 1024 * 1024, backupCount=3
        )
        return handler
    except Exception:
        # Fallback to user home if folder is not writable
        fallback_dir = os.path.join(os.path.expanduser("~"), ".dons_sysmon")
        os.makedirs(fallback_dir, exist_ok=True)
        fallback_path = os.path.join(fallback_dir, LOG_FILE_NAME)
        handler = RotatingFileHandler(
            fallback_path, maxBytes=2 * 1024 * 1024, backupCount=3
        )
        return handler

log_handler = _create_log_handler(LOG_FILE)
fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log_handler.setFormatter(fmt)

console_handler = logging.StreamHandler()
console_handler.setFormatter(fmt)

logger.addHandler(log_handler)
logger.addHandler(console_handler)

# ==============================
# Config loader
# ==============================

def load_or_create_config(path: str | None = None):
    """
    Load JSON config from disk, or create a default one if missing.
    Apply values into global constants.
    """
    global CONFIG
    global UPDATE_INTERVAL_SEC, HIGH_RAM_THRESHOLD, HIGH_CPU_THRESHOLD, HIGH_RAM_USAGE
    global REMOTE_BIND_ADDR, REMOTE_PORT, REMOTE_PASSWORD
    global VIEWER_SERVER_IP, VIEWER_SERVER_PORT, VIEWER_PASSWORD, VIEWER_REFRESH_MS, VIEWER_DEFAULT

    if path is None:
        path = CONFIG_PATH

    default_cfg = {
        # Host / server
        "remote_bind_addr": "0.0.0.0",
        "remote_port": 34255,
        "remote_password": "changeme",
        "update_interval_sec": 2.0,
        "high_ram_threshold": 95,
        "high_cpu_threshold": 70,
        "high_ram_usage": 30,
        "log_level": "INFO",
        "headless_default": False,

        # Viewer / client
        "viewer_default": False,
        "viewer_server_ip": "127.0.0.1",
        "viewer_server_port": 34255,
        "viewer_password": "",        # if empty, fall back to remote_password
        "viewer_refresh_ms": 1000,
    }

    cfg = default_cfg.copy()

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                cfg.update(loaded)
            else:
                logger.warning("Config file is not a JSON object; using defaults")
        except Exception as e:
            logger.error(f"Failed to read config file '{path}': {e}")
            # Keep defaults, but try to write a fresh one with defaults
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(default_cfg, f, indent=4)
            except Exception as e2:
                logger.error(f"Failed to write default config file: {e2}")
    else:
        # Write default config template
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default_cfg, f, indent=4)
            logger.info(f"Created default config file at '{path}'")
        except Exception as e:
            logger.error(f"Failed to create config file '{path}': {e}")

    CONFIG = cfg

    # Apply logging level (do not log the password)
    level_str = str(cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)

    # Apply numeric thresholds / timers
    try:
        UPDATE_INTERVAL_SEC = float(cfg.get("update_interval_sec", UPDATE_INTERVAL_SEC))
    except Exception:
        logger.warning("Invalid update_interval_sec in config; using default")

    try:
        HIGH_RAM_THRESHOLD = int(cfg.get("high_ram_threshold", HIGH_RAM_THRESHOLD))
    except Exception:
        logger.warning("Invalid high_ram_threshold in config; using default")

    try:
        HIGH_CPU_THRESHOLD = int(cfg.get("high_cpu_threshold", HIGH_CPU_THRESHOLD))
    except Exception:
        logger.warning("Invalid high_cpu_threshold in config; using default")

    try:
        HIGH_RAM_USAGE = int(cfg.get("high_ram_usage", HIGH_RAM_USAGE))
    except Exception:
        logger.warning("Invalid high_ram_usage in config; using default")

    # RCON / remote settings (host/server)
    REMOTE_BIND_ADDR = str(cfg.get("remote_bind_addr", REMOTE_BIND_ADDR))

    try:
        REMOTE_PORT = int(cfg.get("remote_port", REMOTE_PORT))
    except Exception:
        logger.warning("Invalid remote_port in config; using default")

    REMOTE_PASSWORD = str(cfg.get("remote_password", REMOTE_PASSWORD))

    if not REMOTE_PASSWORD or REMOTE_PASSWORD == "changeme":
        logger.warning(
            "REMOTE_PASSWORD is not set or still 'changeme'. "
            "Remote interface is effectively insecure."
        )

    # Viewer defaults
    VIEWER_DEFAULT = bool(cfg.get("viewer_default", False))
    VIEWER_SERVER_IP = str(cfg.get("viewer_server_ip", VIEWER_SERVER_IP))

    try:
        VIEWER_SERVER_PORT = int(cfg.get("viewer_server_port", VIEWER_SERVER_PORT))
    except Exception:
        logger.warning("Invalid viewer_server_port in config; using default")

    cfg_viewer_pw = str(cfg.get("viewer_password", ""))
    if cfg_viewer_pw:
        VIEWER_PASSWORD = cfg_viewer_pw
    else:
        # If viewer_password not set, mirror the remote_password by default
        VIEWER_PASSWORD = REMOTE_PASSWORD

    try:
        VIEWER_REFRESH_MS = int(cfg.get("viewer_refresh_ms", VIEWER_REFRESH_MS))
    except Exception:
        logger.warning("Invalid viewer_refresh_ms in config; using default")

    # Log sanitized config (mask passwords)
    cfg_sanitized = cfg.copy()
    if "remote_password" in cfg_sanitized:
        cfg_sanitized["remote_password"] = "***"
    if "viewer_password" in cfg_sanitized:
        cfg_sanitized["viewer_password"] = "***"
    logger.info(f"Loaded config: {cfg_sanitized}")


# ==============================
# Shared state for host UI + Remote
# ==============================

state_lock = threading.Lock()

shared_state = {
    "snapshot": {
        "timestamp": time.time(),
        "cpu": 0.0,
        "ram": 0.0,
        "disk": 0.0,
        "temp": None,
        "problems": [],  # list of dicts: {pid, name, kind, text}
    }
}

# Per-process tracking (always access under state_lock)
memory_trend = {}  # pid -> [mem1, mem2, ...]
problem_apps = {}  # pid -> {"name": str, "kind": "leak"/"high", "text": str}
last_seen = {}     # pid -> last timestamp

last_sysmain_disable = 0.0

# ==============================
# Helpers (host/collector)
# ==============================

def get_system_temperature():
    try:
        temps_raw = psutil.sensors_temperatures()
        if not temps_raw:
            return None
        temp = max(
            [
                sensor.current
                for dev in temps_raw.values()
                for sensor in dev
                if hasattr(sensor, "current")
            ],
            default=None,
        )
        return temp
    except Exception as e:
        logger.debug(f"get_system_temperature failed: {e}")
        return None


def disable_optional_features():
    global last_sysmain_disable
    if platform.system() != "Windows":
        return

    now = time.time()
    if now - last_sysmain_disable < SYSMAIN_COOLDOWN_SEC:
        return

    import subprocess
    try:
        logger.warning("RAM high: attempting to stop SysMain service")
        subprocess.call(
            [
                "powershell",
                "-Command",
                "Stop-Service -Name SysMain -ErrorAction SilentlyContinue",
            ],
            shell=True,
        )
        last_sysmain_disable = now
    except Exception as e:
        logger.error(f"Failed to disable SysMain: {e}")


def get_main_drive_disk_usage():
    try:
        if platform.system() == "Windows":
            path = shutil.disk_usage("C:\\")
        else:
            path = shutil.disk_usage("/")
        total, used, _free = path.total, path.used, path.free
        return used / total * 100.0
    except Exception as e:
        logger.debug(f"get_main_drive_disk_usage failed: {e}")
        return 0.0


def purge_old_pids(pids_alive, now_ts):
    """
    Purge entries for PIDs that are no longer alive,
    and enforce MAX_TRACKED_PROCS limit.
    Assumes caller holds state_lock.
    """
    # Remove dead PIDs
    dead_pids = [pid for pid in memory_trend.keys() if pid not in pids_alive]
    for pid in dead_pids:
        memory_trend.pop(pid, None)
        problem_apps.pop(pid, None)
        last_seen.pop(pid, None)

    # Enforce MAX_TRACKED_PROCS
    if len(memory_trend) > MAX_TRACKED_PROCS:
        items = sorted(last_seen.items(), key=lambda kv: kv[1])  # oldest first
        to_remove = len(memory_trend) - MAX_TRACKED_PROCS
        for pid, _ts in items:
            if pid in memory_trend:
                memory_trend.pop(pid, None)
            if pid in problem_apps:
                problem_apps.pop(pid, None)
            last_seen.pop(pid, None)
            to_remove -= 1
            if to_remove <= 0:
                break


def build_snapshot(cpu, ram, disk, temp):
    """
    Build a snapshot dict based on current globals.
    Assumes caller holds state_lock.
    """
    problems = []
    for pid, info in problem_apps.items():
        problems.append(
            {
                "pid": pid,
                "name": info.get("name", "unknown"),
                "kind": info.get("kind", "high"),
                "text": info.get("text", ""),
            }
        )

    problems.sort(key=lambda p: (0 if p["kind"] == "leak" else 1, p["pid"]))

    if len(problems) > MAX_PROBLEM_ENTRIES:
        problems = problems[:MAX_PROBLEM_ENTRIES]

    snapshot = {
        "timestamp": time.time(),
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "temp": temp,
        "problems": problems,
    }
    return snapshot


# ==============================
# Collector Thread (host)
# ==============================

def collector_loop():
    logger.info("Collector thread started")

    # Initialize psutil CPU measurement
    psutil.cpu_percent(interval=None)

    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            disk = get_main_drive_disk_usage()
            temp = get_system_temperature()
            now_ts = time.time()

            # Collect process info outside lock
            proc_info_list = []
            for proc in psutil.process_iter(
                ["pid", "name", "memory_percent", "cpu_percent"]
            ):
                try:
                    info = proc.info
                    pid = info["pid"]
                    if pid in (0, 4):
                        continue  # skip system idle/system on Windows
                    proc_info_list.append(
                        {
                            "pid": pid,
                            "name": info.get("name") or f"PID {pid}",
                            "mem": info.get("memory_percent") or 0.0,
                            "cpu": info.get("cpu_percent") or 0.0,
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logger.debug(f"Error reading process info: {e}")
                    continue

            # Update tracking and snapshot under lock
            with state_lock:
                pids_alive = set()
                for pinfo in proc_info_list:
                    pid = pinfo["pid"]
                    name = pinfo["name"]
                    mem = pinfo["mem"]
                    cpu_proc = pinfo["cpu"]
                    pids_alive.add(pid)
                    last_seen[pid] = now_ts

                    # Memory trend
                    trend = memory_trend.setdefault(pid, [])
                    trend.append(mem)
                    if len(trend) > MEMORY_TREND_LENGTH:
                        trend.pop(0)

                    # Detect memory leak
                    leak_detected = False
                    if len(trend) == MEMORY_TREND_LENGTH:
                        mem_start = trend[0]
                        mem_end = trend[-1]
                        increasing = all(
                            earlier < later
                            for earlier, later in zip(trend, trend[1:])
                        )
                        if increasing and (mem_end - mem_start) > MEMORY_LEAK_MIN_INCREASE:
                            text = (
                                f"Leak: RAM {mem_start:.2f}% -> {mem_end:.2f}% "
                                f"over {MEMORY_TREND_LENGTH} samples"
                            )
                            prev = problem_apps.get(pid)
                            if not prev or prev["text"] != text or prev["kind"] != "leak":
                                problem_apps[pid] = {
                                    "name": name,
                                    "kind": "leak",
                                    "text": text,
                                }
                                logger.warning(
                                    f"Memory leak suspected in {name} (PID {pid}): {text}"
                                )
                            leak_detected = True

                    if leak_detected:
                        # Don't run high-usage checks if leak flagged
                        continue

                    # High usage check
                    if mem > HIGH_RAM_USAGE or cpu_proc > HIGH_CPU_THRESHOLD:
                        reasons = []
                        if mem > HIGH_RAM_USAGE:
                            reasons.append(f"RAM {mem:.1f}%")
                        if cpu_proc > HIGH_CPU_THRESHOLD:
                            reasons.append(f"CPU {cpu_proc:.1f}%")
                        text = "High usage: " + ", ".join(reasons)
                        prev = problem_apps.get(pid)
                        if not prev or prev["text"] != text or prev["kind"] != "high":
                            problem_apps[pid] = {
                                "name": name,
                                "kind": "high",
                                "text": text,
                            }
                            logger.warning(
                                f"High resource usage: {name} (PID {pid}) - {text}"
                            )
                    else:
                        if pid in problem_apps and problem_apps[pid]["kind"] == "high":
                            logger.info(
                                f"Process {problem_apps[pid]['name']} (PID {pid}) "
                                f"no longer high usage"
                            )
                            problem_apps.pop(pid, None)

                # Purge dead or excess PIDs
                purge_old_pids(pids_alive, now_ts)

                # Build and publish snapshot
                snapshot = build_snapshot(cpu, ram, disk, temp)
                shared_state["snapshot"] = snapshot

            if ram > HIGH_RAM_THRESHOLD:
                logger.warning(f"Total RAM high: {ram:.1f}%")
                disable_optional_features()

        except Exception as e:
            logger.exception(f"Collector loop error: {e}")

        time.sleep(UPDATE_INTERVAL_SEC)


# ==============================
# Remote TCP Server (host)
# ==============================

class MonitorRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"PASSWORD?\n")
            pw = self.request.recv(256).strip().decode("utf-8", errors="ignore")

            if pw != REMOTE_PASSWORD:
                self.request.sendall(b"AUTH_FAIL\n")
                return

            self.request.sendall(b"OK\n")  # password accepted

            # --- Persistent loop ---
            while True:
                cmd = self.request.recv(256)
                if not cmd:
                    break

                cmd = cmd.strip().decode("utf-8", errors="ignore")

                if cmd.upper() == "GET":
                    with state_lock:
                        snap = copy.deepcopy(shared_state["snapshot"])

                    snap["timestamp"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.localtime(snap["timestamp"]),
                    )
                    data = json.dumps(snap).encode("utf-8")
                    self.request.sendall(data + b"\n")

                else:
                    self.request.sendall(b"UNKNOWN\n")

        except Exception as e:
            logger.debug(f"Remote handler error: {e}")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_remote_server():
    server = ThreadedTCPServer((REMOTE_BIND_ADDR, REMOTE_PORT), MonitorRequestHandler)
    t = threading.Thread(target=server.serve_forever, name="RemoteServer", daemon=True)
    t.start()
    logger.info(
        f"Remote monitor TCP server listening on {REMOTE_BIND_ADDR}:{REMOTE_PORT}"
    )
    return server


# ==============================
# GUI (shared for host & viewer)
# ==============================

root = None
labels = {}
problem_tree = None

def build_gui(window_title: str):
    global root, labels, problem_tree

    root = tk.Tk()
    root.title(window_title)
    root.geometry("700x500")
    root.resizable(True, True)

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True, padx=10, pady=10)

    labels = {}
    fields = ["CPU Usage", "RAM Usage", "Disk Usage", "Temperature"]

    for field in fields:
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=3)
        label_name = ttk.Label(row, text=field + ":", width=20, anchor="w")
        label_value = ttk.Label(row, text="0", width=40, anchor="w")
        label_name.pack(side="left")
        label_value.pack(side="left")
        labels[field] = label_value

    problem_label = ttk.Label(frame, text="Problematic Processes:", anchor="w")
    problem_label.pack(fill="x", pady=(15, 5))

    problem_frame = ttk.Frame(frame)
    problem_frame.pack(fill="both", expand=True)

    columns = ("pid", "name", "kind", "text")
    problem_tree = ttk.Treeview(
        problem_frame, columns=columns, show="headings", height=10
    )
    problem_tree.heading("pid", text="PID")
    problem_tree.heading("name", text="Process")
    problem_tree.heading("kind", text="Type")
    problem_tree.heading("text", text="Info")

    problem_tree.column("pid", width=60, anchor="center")
    problem_tree.column("name", width=160, anchor="w")
    problem_tree.column("kind", width=80, anchor="center")
    problem_tree.column("text", width=360, anchor="w")

    vsb = ttk.Scrollbar(
        problem_frame, orient="vertical", command=problem_tree.yview
    )
    problem_tree.configure(yscrollcommand=vsb.set)

    problem_tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")

    def on_close():
        logger.info("GUI closed, exiting process")
        os._exit(0)

    root.protocol("WM_DELETE_WINDOW", on_close)

    return root, labels, problem_tree


# ---- Host GUI refresh ----

def refresh_host_ui():
    try:
        with state_lock:
            snap = copy.deepcopy(shared_state["snapshot"])
    except Exception:
        if root is not None:
            root.after(1000, refresh_host_ui)
        return

    labels["CPU Usage"].config(text=f"{snap['cpu']:.1f}%")
    labels["RAM Usage"].config(text=f"{snap['ram']:.1f}%")
    labels["Disk Usage"].config(text=f"{snap['disk']:.1f}% (capacity)")

    if snap["temp"] is None:
        labels["Temperature"].config(text="Unavailable")
    else:
        labels["Temperature"].config(text=f"{snap['temp']:.1f} °C")

    for row in problem_tree.get_children():
        problem_tree.delete(row)

    for p in snap["problems"]:
        problem_tree.insert(
            "", "end",
            values=(p["pid"], p["name"], p["kind"], p["text"]),
        )

    if root is not None:
        root.after(1000, refresh_host_ui)


# ==============================
# Viewer / remote client
# ==============================

viewer_sock = None
viewer_connected = False

def viewer_connect():
    global viewer_sock, viewer_connected

    # Close old socket if needed
    if viewer_sock:
        try:
            viewer_sock.close()
        except Exception:
            pass

    viewer_sock = None
    viewer_connected = False

    try:
        s = socket.create_connection((VIEWER_SERVER_IP, VIEWER_SERVER_PORT), timeout=3)
        s.settimeout(3.0)

        banner = s.recv(1024).decode("utf-8", errors="ignore")

        if not banner.startswith("PASSWORD?"):
            raise Exception("Bad handshake")

        s.sendall((VIEWER_PASSWORD + "\n").encode("utf-8"))

        resp = s.recv(1024).decode("utf-8", errors="ignore")
        if not resp.startswith("OK"):
            raise Exception("Password rejected")

        viewer_sock = s
        viewer_connected = True
        logger.info(f"Viewer connected to {VIEWER_SERVER_IP}:{VIEWER_SERVER_PORT}")
    except Exception as e:
        viewer_connected = False
        logger.warning(f"Viewer connection failed: {e}")


def viewer_fetch_snapshot():
    global viewer_sock, viewer_connected

    if not viewer_connected or viewer_sock is None:
        viewer_connect()
        if not viewer_connected:
            return None

    try:
        viewer_sock.sendall(b"GET\n")
        data = viewer_sock.recv(65535)
        if not data:
            viewer_connected = False
            return None

        # Server sends JSON + newline
        text = data.decode("utf-8", errors="ignore").strip()
        return json.loads(text)

    except Exception as e:
        logger.debug(f"Viewer fetch failed: {e}")
        viewer_connected = False
        return None


def refresh_viewer_ui():
    snap = viewer_fetch_snapshot()
    if not snap:
        # Show disconnected info but keep scheduling updates
        labels["CPU Usage"].config(text="N/A (disconnected)")
        labels["RAM Usage"].config(text="N/A")
        labels["Disk Usage"].config(text="N/A")
        labels["Temperature"].config(text="Unavailable")

        for row in problem_tree.get_children():
            problem_tree.delete(row)

        if root is not None:
            root.after(VIEWER_REFRESH_MS, refresh_viewer_ui)
        return

    labels["CPU Usage"].config(text=f"{snap['cpu']:.1f}%")
    labels["RAM Usage"].config(text=f"{snap['ram']:.1f}%")
    labels["Disk Usage"].config(text=f"{snap['disk']:.1f}% (remote)")

    if snap["temp"] is None:
        labels["Temperature"].config(text="Unavailable")
    else:
        labels["Temperature"].config(text=f"{snap['temp']:.1f} °C")

    for row in problem_tree.get_children():
        problem_tree.delete(row)

    for p in snap["problems"]:
        problem_tree.insert(
            "", "end",
            values=(p["pid"], p["name"], p["kind"], p["text"]),
        )

    if root is not None:
        root.after(VIEWER_REFRESH_MS, refresh_viewer_ui)


# ==============================
# Main
# ==============================

def parse_args():
    parser = argparse.ArgumentParser(description="Don's System Monitor (host/viewer)")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run host mode without GUI (logging + remote TCP interface only)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config file (JSON). If omitted, uses sysmon.config.json next to the exe/script.",
    )
    parser.add_argument(
        "--mode",
        choices=["host", "viewer"],
        default=None,
        help="Run as 'host' (collector+server) or 'viewer' (remote client GUI).",
    )

    # Viewer overrides
    parser.add_argument(
        "--server-ip",
        type=str,
        default=None,
        help="Viewer: IP / hostname of remote host to connect to.",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=None,
        help="Viewer: TCP port of remote host (defaults to config viewer_server_port).",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Viewer: password for remote host (defaults to config viewer_password / remote_password).",
    )
    parser.add_argument(
        "--refresh-ms",
        type=int,
        default=None,
        help="Viewer: UI refresh interval in ms (defaults to viewer_refresh_ms).",
    )

    return parser.parse_args()


def main():
    global VIEWER_SERVER_IP, VIEWER_SERVER_PORT, VIEWER_PASSWORD, VIEWER_REFRESH_MS

    args = parse_args()

    load_or_create_config(args.config)

    # Decide mode: CLI overrides config
    if args.mode is not None:
        mode = args.mode
    else:
        mode = "viewer" if VIEWER_DEFAULT else "host"

    logger.info(f"Effective mode: {mode}")

    if mode == "host":
        # Host: collector + remote server (+ optional GUI)
        collector_thread = threading.Thread(
            target=collector_loop, name="Collector", daemon=True
        )
        collector_thread.start()

        start_remote_server()

        headless_cfg = bool(CONFIG.get("headless_default", False))
        effective_headless = args.headless or headless_cfg

        if not effective_headless:
            build_gui("Don's System Monitor (Host)")
            root.after(1000, refresh_host_ui)
            logger.info("Starting Tkinter mainloop (host)")
            root.mainloop()
        else:
            logger.info("Running in host headless mode (no GUI)")
            try:
                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                logger.info("Shutting down from KeyboardInterrupt")

    else:
        # Viewer: remote-only GUI client
        # Apply CLI overrides for viewer
        if args.server_ip:
            VIEWER_SERVER_IP = args.server_ip
        if args.server_port:
            VIEWER_SERVER_PORT = args.server_port
        if args.password:
            VIEWER_PASSWORD = args.password
        if args.refresh_ms:
            VIEWER_REFRESH_MS = args.refresh_ms

        logger.info(
            f"Viewer connecting to {VIEWER_SERVER_IP}:{VIEWER_SERVER_PORT}, "
            f"refresh={VIEWER_REFRESH_MS}ms"
        )

        build_gui(f"Don's System Monitor (Viewer: {VIEWER_SERVER_IP})")
        root.after(1000, refresh_viewer_ui)
        logger.info("Starting Tkinter mainloop (viewer)")
        root.mainloop()


if __name__ == "__main__":
    main()
