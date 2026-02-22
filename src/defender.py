import subprocess
import time
import os
import json
from pathlib import Path
from typing import List, Set, Dict, Optional

class Defender:
    def __init__(self, dry_run: bool = True, flush_timeout: int = 300):
        self.dry_run = dry_run
        self.whitelist: Set[str] = {'127.0.0.1', '0.0.0.0'}
        self.mac_whitelist: Set[str] = set()
        self.active_blocks: Dict[str, float] = {}  # ip -> timestamp
        self.flush_timeout = flush_timeout
        self.is_linux = os.uname().sysname == 'Linux'
        self.whitelist_path = Path('whitelist.json')

    def load_whitelist(self):
        """Loads whitelist from shared JSON file."""
        if not self.whitelist_path.exists():
            return
        try:
            data = json.loads(self.whitelist_path.read_text())
            for ip in data.get('ips', []): self.whitelist.add(ip)
            for mac in data.get('macs', []): self.mac_whitelist.add(mac)
        except Exception as e:
            print(f"Error loading whitelist: {e}")

    def add_to_whitelist(self, ip: Optional[str] = None, mac: Optional[str] = None):
        if ip: self.whitelist.add(ip)
        if mac: self.mac_whitelist.add(mac)

    def is_protected(self, ip: str, mac: Optional[str] = None) -> bool:
        if ip in self.whitelist:
            return True
        if mac and mac in self.mac_whitelist:
            return True
        return False

    def block_ip(self, ip: str) -> dict:
        if self.is_protected(ip):
            return {"status": "skipped", "reason": "whitelisted"}
        
        if self.is_linux:
            cmd = ["sudo", "nft", "add", "element", "inet", "filter", "blackhole", f"{{ {ip} }}"]
        else:
            # macOS pfctl logic
            cmd = ["sudo", "pfctl", "-a", "network_defence", "-t", "blocked_ips", "-T", "add", ip]

        if self.dry_run:
            self.active_blocks[ip] = time.time()
            return {"cmd": " ".join(cmd), "status": "dry-run"}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                self.active_blocks[ip] = time.time()
            return {"cmd": " ".join(cmd), "status": "success" if res.returncode == 0 else "failed", "stderr": res.stderr}
        except Exception as e:
            return {"error": str(e)}

    def flush_expired_rules(self) -> List[str]:
        now = time.time()
        expired = [ip for ip, ts in self.active_blocks.items() if now - ts > self.flush_timeout]
        flushed = []

        for ip in expired:
            if not self.dry_run:
                if self.is_linux:
                    cmd = ["sudo", "nft", "delete", "element", "inet", "filter", "blackhole", f"{{ {ip} }}"]
                else:
                    cmd = ["sudo", "pfctl", "-a", "network_defence", "-t", "blocked_ips", "-T", "delete", ip]
                subprocess.run(cmd, capture_output=True)
            
            self.active_blocks.pop(ip, None)
            flushed.append(ip)
        
        return flushed

    def flush_all(self) -> List[str]:
        """Manually flush all active blocks."""
        ips_to_flush = list(self.active_blocks.keys())
        flushed = []
        for ip in ips_to_flush:
            if not self.dry_run:
                if self.is_linux:
                    cmd = ["sudo", "nft", "delete", "element", "inet", "filter", "blackhole", f"{{ {ip} }}"]
                else:
                    cmd = ["sudo", "pfctl", "-a", "network_defence", "-t", "blocked_ips", "-T", "delete", ip]
                subprocess.run(cmd, capture_output=True)
            self.active_blocks.pop(ip, None)
            flushed.append(ip)
        return flushed
