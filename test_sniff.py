import sys
import os
from src.tshark_wrapper import capture_to_pcap
from src.packet_to_flow import pcap_to_flows
import pandas as pd
import pyshark

try:
    print("Capturing...")
    capture_to_pcap("en0", 5, "test.pcap")
    print(f"File size: {os.path.getsize('test.pcap')}")
    cap = pyshark.FileCapture('test.pcap')
    pkts = 0
    for pkt in cap:
        pkts += 1
    print(f"Total pure packets: {pkts}")
    cap.close()

    print("Parsing flows...")
    pcap_to_flows("test.pcap", "test_flows.csv")
    df = pd.read_csv("test_flows.csv")
    print(f"Rows in DF: {len(df)}")
    print(df)
except Exception as e:
    import traceback
    traceback.print_exc()

