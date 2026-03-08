#!/usr/bin/env python3
"""
Network Access Guard - Intercepts network requests and requires ZK proof.
Only affects network access; local access remains transparent.
"""

import os
import sys
import json
import socket
import hashlib
import threading
import argparse
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

ZK_DIR = Path.home() / ".zkp"
KEYS_FILE = ZK_DIR / "keys" / "identity.json"
CONFIG_FILE = ZK_DIR / "config.yaml"
GUARD_PORT = 18060  # Default, will be overridden by config

class GuardedRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler that requires ZK proof for external access."""
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def do_GET(self):
        self.handle_request("GET")
    
    def do_POST(self):
        self.handle_request("POST")
    
    def handle_request(self, method):
        """Process request with ZK verification."""
        # Check if it's a local request
        client_ip = self.client_address[0]
        is_local = client_ip in ("127.0.0.1", "::1", "localhost")
        
        if is_local:
            # Local access - allow directly (transparent)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-ZKP-Status", "local")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "access": "local",
                "message": "Local access granted"
            }).encode())
            return
        
        # Network access - require ZK proof
        proof = self.headers.get("X-ZKP-Proof")
        
        if not proof:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-ZKP-Status", "proof_required")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "ZK proof required for network access",
                "hint": "Include X-ZKP-Proof header"
            }).encode())
            return
        
        # Verify proof
        try:
            proof_data = json.loads(proof)
            if not verify_zk_proof(proof_data):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-ZKP-Status", "invalid_proof")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "error",
                    "message": "Invalid ZK proof"
                }).encode())
                return
            
            # Proof valid - allow access
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-ZKP-Status", "verified")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "access": "network_verified",
                "message": "ZK proof verified"
            }).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": str(e)
            }).encode())


def verify_zk_proof(proof: dict) -> bool:
    """Verify ZK proof."""
    import yaml
    
    # Load config
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f)
    else:
        config = {"zkp": {"difficulty": 16}}
    
    difficulty = config.get("zkp", {}).get("difficulty", 16)
    prefix = "0" * difficulty
    
    # Check proof of work
    pow_input = f"{proof.get('public_key', '')}{proof['challenge']}{proof['counter']}"
    pow_hash = hashlib.sha256(pow_input.encode()).hexdigest()
    
    if not pow_hash.startswith(prefix):
        return False
    
    # Load keys and verify
    if KEYS_FILE.exists():
        with open(KEYS_FILE) as f:
            keys = json.load(f)
        
        # Verify response matches
        expected_response = hashlib.sha256(
            (keys["secret_key"] + proof["challenge"]).encode()
        ).hexdigest()
        
        return proof["response"] == expected_response
    
    return False


def start_guard(port: int = None):
    """Start the network guard."""
    global GUARD_PORT
    
    if port:
        GUARD_PORT = port
    elif CONFIG_FILE.exists():
        import yaml
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f)
            GUARD_PORT = config.get("protection", {}).get("guard_port", 18060)
    
    server = HTTPServer(("0.0.0.0", GUARD_PORT), GuardedRequestHandler)
    print(f"🛡️ Network guard started on port {GUARD_PORT}")
    print(f"   Local access: Transparent (no ZK required)")
    print(f"   Network access: ZK proof required")
    print()
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Guard stopped")
        server.shutdown()


def check_status():
    """Check guard status."""
    print("=" * 40)
    print("ZKP Network Guard Status")
    print("=" * 40)
    
    # Check if keys exist
    if KEYS_FILE.exists():
        with open(KEYS_FILE) as f:
            keys = json.load(f)
        print(f"✅ ZKP Keys: {keys['public_key'][:16]}...")
    else:
        print("❌ ZKP Keys not found")
        return
    
    # Check if config exists
    if CONFIG_FILE.exists():
        import yaml
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f)
        print(f"✅ Config: {CONFIG_FILE}")
        print(f"   Guard port: {config.get('protection', {}).get('guard_port', 18060)}")
        print(f"   Auto-encrypt: {config.get('protection', {}).get('auto_encrypt_idle_seconds', 300)}s")
    else:
        print("⚠️ Config not found")
    
    # Test local connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', GUARD_PORT))
        sock.close()
        
        if result == 0:
            print(f"✅ Guard running on port {GUARD_PORT}")
        else:
            print(f"⚠️ Guard not running on port {GUARD_PORT}")
    except:
        print(f"⚠️ Cannot check guard status")
    
    print()


def install_guard():
    """Install guard as a service (placeholder for now)."""
    print("Installing network guard...")
    print("Note: Full service installation requires:")
    print("  - LaunchAgent (macOS)")
    print("  - systemd (Linux)")
    print("  - Windows Service")
    print()
    print("For now, run 'python3 scripts/guard.py' to start manually.")
    print()


def main():
    parser = argparse.ArgumentParser(description="ZKP Network Guard")
    parser.add_argument("--install", action="store_true", help="Install guard as service")
    parser.add_argument("--status", action="store_true", help="Check guard status")
    parser.add_argument("--port", type=int, help="Port to listen on")
    
    args = parser.parse_args()
    
    if args.status:
        check_status()
    elif args.install:
        install_guard()
    else:
        start_guard(args.port)


if __name__ == "__main__":
    main()
