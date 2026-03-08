#!/usr/bin/env python3
"""
Auto-Protection - Automatically encrypt files after idle period.
Monitors conversation activity and encrypts when idle.
"""

import os
import sys
import json
import time
import hashlib
import argparse
import threading
from pathlib import Path
from datetime import datetime, timedelta

ZK_DIR = Path.home() / ".zkp"
CONFIG_FILE = ZK_DIR / "config.yaml"
KEYS_FILE = ZK_DIR / "keys" / "identity.json"
LAST_ACCESS_FILE = ZK_DIR / "last_access.json"

# Default idle time: 5 minutes
DEFAULT_IDLE_TIME = 300

def load_config():
    """Load configuration."""
    import yaml
    
    if not CONFIG_FILE.exists():
        return {"protection": {"auto_encrypt_idle_seconds": DEFAULT_IDLE_TIME}}
    
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

def get_last_access_time() -> datetime:
    """Get last access time."""
    if LAST_ACCESS_FILE.exists():
        with open(LAST_ACCESS_FILE) as f:
            data = json.load(f)
            return datetime.fromisoformat(data["last_access"])
    
    return datetime.now()

def update_last_access_time():
    """Update last access time."""
    data = {"last_access": datetime.now().isoformat()}
    with open(LAST_ACCESS_FILE, 'w') as f:
        json.dump(data, f)

def encrypt_conversations():
    """Encrypt conversation files."""
    workspace = Path.home() / ".openclaw" / "workspace"
    memory_dir = workspace / "memory"
    
    if not memory_dir.exists():
        print("No memory directory found")
        return
    
    # Import encryption function
    sys.path.insert(0, str(Path(__file__).parent))
    from encrypt import encrypt_directory, DATA_DIR
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Encrypting conversations...")
    encrypt_directory(memory_dir)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Encryption complete")

def check_and_encrypt():
    """Check idle time and encrypt if needed."""
    config = load_config()
    idle_time = config.get("protection", {}).get("auto_encrypt_idle_seconds", DEFAULT_IDLE_TIME)
    
    last_access = get_last_access_time()
    now = datetime.now()
    idle_seconds = (now - last_access).total_seconds()
    
    if idle_seconds >= idle_time:
        print(f"Idle for {idle_seconds:.0f}s (threshold: {idle_time}s)")
        encrypt_conversations()
    else:
        print(f"Active - idle for {idle_seconds:.0f}s (threshold: {idle_time}s)")

def monitor_loop():
    """Main monitoring loop."""
    config = load_config()
    idle_time = config.get("protection", {}).get("auto_encrypt_idle_seconds", DEFAULT_IDLE_TIME)
    
    print(f"🛡️ Auto-protection started (idle threshold: {idle_time}s)")
    print("Press Ctrl+C to stop")
    print()
    
    while True:
        check_and_encrypt()
        time.sleep(60)  # Check every minute

def daemon_mode():
    """Run as background daemon."""
    # Create PID file
    pid_file = ZK_DIR / "protect_daemon.pid"
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    
    try:
        monitor_loop()
    except KeyboardInterrupt:
        print("\n🛑 Daemon stopped")
        pid_file.unlink()

def status():
    """Show protection status."""
    print("=" * 40)
    print("Auto-Protection Status")
    print("=" * 40)
    
    config = load_config()
    idle_time = config.get("protection", {}).get("auto_encrypt_idle_seconds", DEFAULT_IDLE_TIME)
    
    last_access = get_last_access_time()
    now = datetime.now()
    idle_seconds = (now - last_access).total_seconds()
    
    print(f"Idle threshold: {idle_time}s")
    print(f"Current idle: {idle_seconds:.0f}s")
    print(f"Last activity: {last_access.strftime('%H:%M:%S')}")
    
    if idle_seconds >= idle_time:
        print("⚠️ Should encrypt (idle exceeded threshold)")
    else:
        print("✅ Active (within threshold)")
    
    # Check encrypted files
    data_dir = ZK_DIR / "data"
    if data_dir.exists():
        files = list(data_dir.glob("*.enc"))
        print(f"\nEncrypted files: {len(files)}")
    
    # Check if daemon is running
    pid_file = ZK_DIR / "protect_daemon.pid"
    if pid_file.exists():
        with open(pid_file) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, 0)
            print(f"✅ Daemon running (PID: {pid})")
        except OSError:
            print(f"⚠️ Daemon PID file exists but process not running")
            pid_file.unlink()
    else:
        print("⚠️ Daemon not running")
    
    print()

def main():
    parser = argparse.ArgumentParser(description="Auto-Protection Daemon")
    parser.add_argument("--start", action="store_true", help="Start daemon")
    parser.add_argument("--stop", action="store_true", help="Stop daemon")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--encrypt-now", action="store_true", help="Encrypt now")
    
    args = parser.parse_args()
    
    if args.status:
        status()
    elif args.encrypt_now:
        encrypt_conversations()
    elif args.start:
        daemon_mode()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
