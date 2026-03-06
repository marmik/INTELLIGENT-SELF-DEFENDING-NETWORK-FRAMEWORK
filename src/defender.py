import subprocess
import time
import os
import json
from pathlib import Path
from typing import List, Set, Dict, Optional

import ipaddress

class Defender:
    def __init__(
        self,
        dry_run: bool = True,
        flush_timeout: int = 300,
        iface: str = "en0",
        honeypot_ip: str = "127.0.0.1",
        honeypot_port: int = 8080,
    ):
        self.dry_run = dry_run
        self.whitelist: Set[str] = {'127.0.0.1', '0.0.0.0'}
        self.mac_whitelist: Set[str] = set()
        self.active_blocks: Dict[str, float] = {}  # ip -> timestamp
        self.persistent_blocks: Set[str] = set()    # IPs blocked until manual flush
        self.flush_timeout = flush_timeout
        self.is_linux = os.uname().sysname == 'Linux'
        self.whitelist_path = Path('whitelist.json')
        self.iface = iface
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        
        self.infra_immunity: Set[str] = {
            # DNS providers
            '8.8.8.8', '8.8.4.4',      # Google DNS
            '1.1.1.1', '1.0.0.1',      # Cloudflare DNS
            '9.9.9.9',                 # Quad9
            '192.168.1.1',             # Default Gateway
            '10.0.0.1',                # Default Gateway
            '127.0.0.1',               # Loopback
            
            # Google Services
            '216.239.32.0/19',         # covers 216.239.38.223
            '216.58.192.0/19',
            '172.217.0.0/16',
            '142.250.0.0/15',
            '64.233.160.0/19',
            '66.102.0.0/20',
            '66.249.64.0/19',          # Google Bot
            '72.14.192.0/18',
            '74.125.0.0/16',
            '108.177.0.0/17',
            '173.194.0.0/16',
            '209.85.128.0/17'
        }

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

    def is_protected(self, ip_str: str, mac: Optional[str] = None) -> bool:
        # Check direct whitelist and MAC first (fast)
        if ip_str in self.whitelist:
            return True
        if mac and mac in self.mac_whitelist:
            return True
            
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for immune in self.infra_immunity:
                if '/' in immune:
                    if ip_obj in ipaddress.ip_network(immune):
                        return True
                elif ip_str == immune:
                    return True
        except Exception as e:
            print(f"IP Check Error for {ip_str}: {e}")

        # fall back to the broader CIDR-based detection in ml.utils
        try:
            from ml.utils import is_known_infra
            if is_known_infra(ip_str):
                return True
        except ImportError:
            pass

        return False

    def throttle_ip(self, ip: str, rate_kbps: int = 50) -> dict:
        """Throttles an IP using macOS dnctl/pfctl pipes."""
        if self.is_protected(ip):
            return {"status": "skipped", "reason": "whitelisted"}
        
        # Logic for macOS: Create a dummynet pipe and route IP through it
        pipe_id = 100
        cmd_pipe = ["dnctl", "pipe", str(pipe_id), "config", "bw", f"{rate_kbps}Kbit/s"]
        cmd_rule = ["pfctl", "-a", "network_defence/throttle", "-t", f"throttled_{ip}", "-T", "add", ip]
        
        if self.dry_run:
            return {"status": "dry-run", "action": "throttle", "rate": f"{rate_kbps}kbps"}

        try:
            # 1. Ensure pipe exists
            subprocess.run(cmd_pipe, capture_output=True)
            # 2. Add IP to throttled table
            subprocess.run(cmd_rule, capture_output=True)
            self.active_blocks[ip] = time.time() # Mark for cleanup
            return {"status": "success", "action": "throttle", "ip": ip}
        except Exception as e:
            return {"error": str(e)}

    def _ensure_deception_anchor(self, honey_ip: str, honey_port: int) -> Optional[str]:
        if self.is_linux:
            return None
        rules = (
            "table <deceived_ips> persist\n"
            f"rdr pass on {self.iface} proto tcp from <deceived_ips> to any -> {honey_ip} port {honey_port}\n"
        )
        cmd = ["pfctl", "-a", "network_defence/deception", "-f", "-"]
        res = subprocess.run(cmd, input=rules, capture_output=True, text=True)
        if res.returncode != 0:
            return res.stderr or "failed to load deception anchor"
        return None

    def redirect_to_honeypot(self, ip: str, honey_ip: Optional[str] = None, honey_port: Optional[int] = None) -> dict:
        """Redirects malicious traffic to a honeypot (Deceptive Defense)."""
        if self.is_protected(ip):
            return {"status": "skipped", "reason": "whitelisted"}

        target_ip = honey_ip or self.honeypot_ip
        target_port = honey_port or self.honeypot_port
            
        if self.is_linux:
            cmd = ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "dnat", "to", f"{target_ip}:{target_port}"]
        else:
            err = self._ensure_deception_anchor(target_ip, target_port)
            if err:
                return {"status": "failed", "error": err}
            cmd = ["pfctl", "-a", "network_defence/deception", "-t", "deceived_ips", "-T", "add", ip]
            
        if self.dry_run:
            self.active_blocks[ip] = time.time()
            return {"status": "dry-run", "action": "deception", "target": f"{target_ip}:{target_port}"}

        try:
            if self.is_linux:
                subprocess.run(cmd, capture_output=True, text=True)
            else:
                subprocess.run(cmd, capture_output=True, text=True)
                
            self.active_blocks[ip] = time.time()
            return {"status": "success", "action": "deception", "ip": ip, "honeypot": f"{target_ip}:{target_port}"}
        except Exception as e:
            return {"error": str(e)}

    def block_ip(self, ip: str, persistent: bool = False) -> dict:
        if self.is_protected(ip):
            return {"status": "skipped", "reason": "whitelisted"}
        
        if self.is_linux:
            cmd = ["nft", "add", "element", "inet", "filter", "blackhole", f"{{ {ip} }}"]
        else:
            # macOS pfctl logic
            cmd = ["pfctl", "-a", "network_defence", "-t", "blocked_ips", "-T", "add", ip]

        if self.dry_run:
            if persistent:
                self.persistent_blocks.add(ip)
            else:
                self.active_blocks[ip] = time.time()
            return {"cmd": " ".join(cmd), "status": "dry-run", "persistent": persistent}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                if persistent:
                    self.persistent_blocks.add(ip)
                else:
                    self.active_blocks[ip] = time.time()
            return {"cmd": " ".join(cmd), "status": "success" if res.returncode == 0 else "failed", "stderr": res.stderr, "persistent": persistent}
        except Exception as e:
            return {"error": str(e)}

    def flush_expired_rules(self) -> List[str]:
        now = time.time()
        expired = [ip for ip, ts in self.active_blocks.items() if now - ts > self.flush_timeout]
        flushed = []

        for ip in expired:
            if not self.dry_run:
                if self.is_linux:
                    cmd = ["nft", "delete", "element", "inet", "filter", "blackhole", f"{{ {ip} }}"]
                else:
                    cmd = ["pfctl", "-a", "network_defence", "-t", "blocked_ips", "-T", "delete", ip]
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
                    cmd = ["nft", "delete", "element", "inet", "filter", "blackhole", f"{{ {ip} }}"]
                else:
                    cmd = ["pfctl", "-a", "network_defence", "-t", "blocked_ips", "-T", "delete", ip]
                subprocess.run(cmd, capture_output=True)
            self.active_blocks.pop(ip, None)
            flushed.append(ip)
        return flushed
