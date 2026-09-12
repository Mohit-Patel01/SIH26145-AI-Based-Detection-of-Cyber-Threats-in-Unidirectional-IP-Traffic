from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv

flows = {}


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto

    source_port = None
    destination_port = None

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # Create a unique identifier for the flow
    flow_key = (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    )

    current_time = datetime.now()

    # If this is a new flow
    if flow_key not in flows:

        flows[flow_key] = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_count": 1,
            "total_bytes": len(packet),
            "start_time": current_time,
            "last_time": current_time
        }

    # Existing flow
    else:

        flow = flows[flow_key]

        flow["packet_count"] += 1
        flow["total_bytes"] += len(packet)
        flow["last_time"] = current_time


print("Starting packet capture...")

sniff(
    prn=process_packet,
    count=100
)

print("\nCapture finished.")
print("Total flows:", len(flows))

with open("captured_flows.csv", "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_count",
        "total_bytes",
        "duration"
    ])

    for flow in flows.values():

        duration = (
            flow["last_time"] - flow["start_time"]
        ).total_seconds()

        writer.writerow([
            flow["source_ip"],
            flow["destination_ip"],
            flow["source_port"],
            flow["destination_port"],
            flow["protocol"],
            flow["packet_count"],
            flow["total_bytes"],
            duration
        ])

print("\nFlows saved to captured_flows.csv")