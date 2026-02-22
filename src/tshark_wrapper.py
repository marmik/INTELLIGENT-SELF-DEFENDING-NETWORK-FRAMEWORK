import subprocess
import os
from pathlib import Path

def capture_to_pcap(interface: str, duration: int, output_pcap: str) -> str:
    """Run tshark to capture for `duration` seconds and write to `output_pcap`.

    Requires tshark installed and accessible.
    """
    out_dir = Path(output_pcap).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "tshark",
        "-i",
        interface,
        "-a",
        f"duration:{duration}",
        "-w",
        output_pcap,
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr}")
    return output_pcap
