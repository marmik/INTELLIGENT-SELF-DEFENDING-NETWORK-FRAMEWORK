import subprocess
import os
from pathlib import Path

def capture_to_pcap(interfaces: list, duration: int, output_pcap: str) -> str:
    """Run tshark to capture on multiple interfaces and write to `output_pcap`."""
    out_dir = Path(output_pcap).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    
    cmd = ["tshark"]
    for iface in interfaces:
        cmd += ["-i", iface]
    
    cmd += [
        "-B", "131072",      # 128MB Buffer (KiB units on macOS)
        "-a", f"duration:{duration}",
        "-w", output_pcap,
    ]
    
    # Redirect to DEVNULL to avoid pipe deadlock
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed with code {proc.returncode}")
    return output_pcap
