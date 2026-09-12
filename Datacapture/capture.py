from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv
import numpy as np


flows = {}


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto

    source_port = 0
    destination_port = 0

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # Flow direction
    flow_key = (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    )

    reverse_key = (
        destination_ip,
        source_ip,
        destination_port,
        source_port,
        protocol
    )

    current_time = datetime.now()

    # New flow
    if flow_key not in flows and reverse_key not in flows:

        flows[flow_key] = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,

            "start_time": current_time,
            "last_time": current_time,

            "packets": [],

            "fwd_packets": [],
            "bwd_packets": [],

            "fwd_times": [],
            "bwd_times": [],

            "tcp_flags": [],

            "fwd_tcp_windows": [],
            "bwd_tcp_windows": [],

            "fwd_header_lengths": [],
            "bwd_header_lengths": []
        }

        flow = flows[flow_key]

        direction = "fwd"

    # Existing flow
    elif flow_key in flows:

        flow = flows[flow_key]

        direction = "fwd"

    # Reverse direction of existing flow
    else:

        flow = flows[reverse_key]

        direction = "bwd"


    packet_length = len(packet)

    flow["last_time"] = current_time

    flow["packets"].append({
        "time": current_time,
        "length": packet_length,
        "direction": direction
    })


    if direction == "fwd":

        flow["fwd_packets"].append(packet_length)
        flow["fwd_times"].append(current_time)

    else:

        flow["bwd_packets"].append(packet_length)
        flow["bwd_times"].append(current_time)


    # TCP information
    if TCP in packet:

        flags = packet[TCP].flags

        flow["tcp_flags"].append({
            "flags": flags,
        "direction": direction
        })

        if direction == "fwd":

            flow["fwd_tcp_windows"].append(packet[TCP].window)

        else:

            flow["bwd_tcp_windows"].append(packet[TCP].window)


    # Header length
    if IP in packet:

        ip_header_length = packet[IP].ihl * 4

        if TCP in packet:

            tcp_header_length = packet[TCP].dataofs * 4

        else:

            tcp_header_length = 0

        total_header_length = ip_header_length + tcp_header_length

        if direction == "fwd":

            flow["fwd_header_lengths"].append(
                total_header_length
            )

        else:

            flow["bwd_header_lengths"].append(
                total_header_length
            )


def calculate_mean(values):

    if len(values) == 0:
        return 0

    return np.mean(values)


def calculate_std(values):

    if len(values) <= 1:
        return 0

    return np.std(values)


def calculate_iat(times):

    if len(times) <= 1:
        return []

    times = sorted(times)

    return [
        (times[i] - times[i - 1]).total_seconds() * 1_000_000
        for i in range(1, len(times))
    ]

def calculate_basic_features(flow):

    fwd = flow["fwd_packets"]
    bwd = flow["bwd_packets"]

    all_packets = fwd + bwd

    # Flow duration in microseconds
    duration = (
        flow["last_time"] - flow["start_time"]
    ).total_seconds() * 1_000_000

    # Avoid division by zero
    duration_seconds = duration / 1_000_000

    if duration_seconds == 0:
        duration_seconds = 0.000001

    features = {}

    # Destination port
    features["Destination Port"] = flow["destination_port"]

    # Flow duration
    features["Flow Duration"] = duration

    # Packet counts
    features["Total Fwd Packets"] = len(fwd)
    features["Total Backward Packets"] = len(bwd)

    # Byte counts
    features["Total Length of Fwd Packets"] = sum(fwd)
    features["Total Length of Bwd Packets"] = sum(bwd)

    # Forward packet statistics
    if fwd:
        features["Fwd Packet Length Max"] = max(fwd)
        features["Fwd Packet Length Min"] = min(fwd)
        features["Fwd Packet Length Mean"] = np.mean(fwd)
        features["Fwd Packet Length Std"] = (
            np.std(fwd) if len(fwd) > 1 else 0
        )
    else:
        features["Fwd Packet Length Max"] = 0
        features["Fwd Packet Length Min"] = 0
        features["Fwd Packet Length Mean"] = 0
        features["Fwd Packet Length Std"] = 0

    # Backward packet statistics
    if bwd:
        features["Bwd Packet Length Max"] = max(bwd)
        features["Bwd Packet Length Min"] = min(bwd)
        features["Bwd Packet Length Mean"] = np.mean(bwd)
        features["Bwd Packet Length Std"] = (
            np.std(bwd) if len(bwd) > 1 else 0
        )
    else:
        features["Bwd Packet Length Max"] = 0
        features["Bwd Packet Length Min"] = 0
        features["Bwd Packet Length Mean"] = 0
        features["Bwd Packet Length Std"] = 0

    # Flow rates
    total_bytes = sum(all_packets)
    total_packets = len(all_packets)

    features["Flow Bytes/s"] = (
        total_bytes / duration_seconds
    )

    features["Flow Packets/s"] = (
        total_packets / duration_seconds
    )

    return features

def calculate_timing_features(flow):

    all_times = [
        packet["time"]
        for packet in flow["packets"]
    ]

    fwd_times = flow["fwd_times"]
    bwd_times = flow["bwd_times"]

    # Calculate inter-arrival times
    flow_iat = calculate_iat(all_times)
    fwd_iat = calculate_iat(fwd_times)
    bwd_iat = calculate_iat(bwd_times)

    features = {}

    # Flow IAT
    features["Flow IAT Mean"] = calculate_mean(flow_iat)
    features["Flow IAT Std"] = calculate_std(flow_iat)

    features["Flow IAT Max"] = (
        max(flow_iat) if flow_iat else 0
    )

    features["Flow IAT Min"] = (
        min(flow_iat) if flow_iat else 0
    )

    # Forward IAT
    features["Fwd IAT Total"] = sum(fwd_iat)

    features["Fwd IAT Mean"] = calculate_mean(fwd_iat)
    features["Fwd IAT Std"] = calculate_std(fwd_iat)

    features["Fwd IAT Max"] = (
        max(fwd_iat) if fwd_iat else 0
    )

    features["Fwd IAT Min"] = (
        min(fwd_iat) if fwd_iat else 0
    )

    # Backward IAT
    features["Bwd IAT Total"] = sum(bwd_iat)

    features["Bwd IAT Mean"] = calculate_mean(bwd_iat)
    features["Bwd IAT Std"] = calculate_std(bwd_iat)

    features["Bwd IAT Max"] = (
        max(bwd_iat) if bwd_iat else 0
    )

    features["Bwd IAT Min"] = (
        min(bwd_iat) if bwd_iat else 0
    )

    return features

def calculate_flag_features(flow):

    features = {}

    fwd_psh = 0
    bwd_psh = 0
    fwd_urg = 0
    bwd_urg = 0

    fin_count = 0
    syn_count = 0
    rst_count = 0
    psh_count = 0
    ack_count = 0
    urg_count = 0
    cwe_count = 0
    ece_count = 0

    for item in flow["tcp_flags"]:

        flags = item["flags"]
        direction = item["direction"]

        if flags & 0x01:       # FIN
            fin_count += 1

        if flags & 0x02:       # SYN
            syn_count += 1

        if flags & 0x04:       # RST
            rst_count += 1

        if flags & 0x08:       # PSH
            psh_count += 1

            if direction == "fwd":
                fwd_psh += 1
            else:
                bwd_psh += 1

        if flags & 0x10:       # ACK
            ack_count += 1

        if flags & 0x20:       # URG
            urg_count += 1

            if direction == "fwd":
                fwd_urg += 1
            else:
                bwd_urg += 1

        if flags & 0x40:       # ECE
            ece_count += 1

        if flags & 0x80:       # CWR
            cwe_count += 1

    features["Fwd PSH Flags"] = fwd_psh
    features["Bwd PSH Flags"] = bwd_psh
    features["Fwd URG Flags"] = fwd_urg
    features["Bwd URG Flags"] = bwd_urg

    features["FIN Flag Count"] = fin_count
    features["SYN Flag Count"] = syn_count
    features["RST Flag Count"] = rst_count
    features["PSH Flag Count"] = psh_count
    features["ACK Flag Count"] = ack_count
    features["URG Flag Count"] = urg_count
    features["CWE Flag Count"] = cwe_count
    features["ECE Flag Count"] = ece_count

    return features

def calculate_packet_features(flow):

    fwd = flow["fwd_packets"]
    bwd = flow["bwd_packets"]
    all_packets = fwd + bwd

    features = {}

    # Header lengths
    features["Fwd Header Length"] = sum(
        flow["fwd_header_lengths"]
    )

    features["Bwd Header Length"] = sum(
        flow["bwd_header_lengths"]
    )

    # Duration in seconds
    duration = (
        flow["last_time"] - flow["start_time"]
    ).total_seconds()

    if duration == 0:
        duration = 0.000001

    # Packets per second
    features["Fwd Packets/s"] = len(fwd) / duration
    features["Bwd Packets/s"] = len(bwd) / duration

    # All packet length statistics
    if all_packets:

        features["Min Packet Length"] = min(all_packets)
        features["Max Packet Length"] = max(all_packets)
        features["Packet Length Mean"] = np.mean(all_packets)
        features["Packet Length Std"] = (
            np.std(all_packets)
            if len(all_packets) > 1
            else 0
        )
        features["Packet Length Variance"] = (
            np.var(all_packets)
            if len(all_packets) > 1
            else 0
        )

    else:

        features["Min Packet Length"] = 0
        features["Max Packet Length"] = 0
        features["Packet Length Mean"] = 0
        features["Packet Length Std"] = 0
        features["Packet Length Variance"] = 0

    # Down / Up ratio
    if len(fwd) == 0:
        features["Down/Up Ratio"] = 0
    else:
        features["Down/Up Ratio"] = len(bwd) / len(fwd)

    # Average packet size
    if all_packets:
        features["Average Packet Size"] = (
            sum(all_packets) / len(all_packets)
        )
    else:
        features["Average Packet Size"] = 0

    # Average forward segment size
    if fwd:
        features["Avg Fwd Segment Size"] = (
            sum(fwd) / len(fwd)
        )
    else:
        features["Avg Fwd Segment Size"] = 0

    # Average backward segment size
    if bwd:
        features["Avg Bwd Segment Size"] = (
            sum(bwd) / len(bwd)
        )
    else:
        features["Avg Bwd Segment Size"] = 0

    # Duplicate CICIDS feature
    features["Fwd Header Length.1"] = (
        features["Fwd Header Length"]
    )

    return features

def calculate_bulk_subflow_features(flow):

    fwd = flow["fwd_packets"]
    bwd = flow["bwd_packets"]

    features = {}

    # -------------------------------------------------
    # Bulk features
    # -------------------------------------------------
    # We are not currently tracking bulk transfers,
    # so these remain 0 for the prototype.
    
    features["Fwd Avg Bytes/Bulk"] = 0
    features["Fwd Avg Packets/Bulk"] = 0
    features["Fwd Avg Bulk Rate"] = 0

    features["Bwd Avg Bytes/Bulk"] = 0
    features["Bwd Avg Packets/Bulk"] = 0
    features["Bwd Avg Bulk Rate"] = 0

    # -------------------------------------------------
    # Subflow features
    # -------------------------------------------------

    features["Subflow Fwd Packets"] = len(fwd)

    features["Subflow Fwd Bytes"] = sum(fwd)

    features["Subflow Bwd Packets"] = len(bwd)

    features["Subflow Bwd Bytes"] = sum(bwd)

    # -------------------------------------------------
    # Initial TCP window size
    # -------------------------------------------------

    if flow["fwd_tcp_windows"]:
        features["Init_Win_bytes_forward"] = (
            flow["fwd_tcp_windows"][0]
        )
    else:
        features["Init_Win_bytes_forward"] = 0

    if flow["bwd_tcp_windows"]:
        features["Init_Win_bytes_backward"] = (
            flow["bwd_tcp_windows"][0]
        )
    else:
        features["Init_Win_bytes_backward"] = 0

    # -------------------------------------------------
    # Active data packets
    # -------------------------------------------------

    features["act_data_pkt_fwd"] = len(fwd)

    # -------------------------------------------------
    # Minimum forward segment size
    # -------------------------------------------------

    if flow["fwd_header_lengths"]:
        features["min_seg_size_forward"] = min(
            flow["fwd_header_lengths"]
        )
    else:
        features["min_seg_size_forward"] = 0

    return features

def calculate_active_idle_features(flow):

    all_times = [
        packet["time"]
        for packet in flow["packets"]
    ]

    features = {}

    active_periods = []
    idle_periods = []

    # Need at least 2 packets to calculate gaps
    if len(all_times) < 2:
        active_periods = []
        idle_periods = []

    else:
        all_times = sorted(all_times)

        gaps = [
            (all_times[i] - all_times[i - 1]).total_seconds()
            * 1_000_000
            for i in range(1, len(all_times))
        ]

        # CICIDS commonly treats a 1-second gap as
        # the boundary between active and idle periods.
        current_active = []

        for gap in gaps:

            if gap <= 1_000_000:
                current_active.append(gap)

            else:
                if current_active:
                    active_periods.append(
                        sum(current_active)
                    )

                idle_periods.append(gap)

                current_active = []

        if current_active:
            active_periods.append(
                sum(current_active)
            )

    # -------------------------------------------------
    # Active features
    # -------------------------------------------------

    if active_periods:

        features["Active Mean"] = np.mean(active_periods)

        features["Active Std"] = (
            np.std(active_periods)
            if len(active_periods) > 1
            else 0
        )

        features["Active Max"] = max(active_periods)

        features["Active Min"] = min(active_periods)

    else:

        features["Active Mean"] = 0
        features["Active Std"] = 0
        features["Active Max"] = 0
        features["Active Min"] = 0

    # -------------------------------------------------
    # Idle features
    # -------------------------------------------------

    if idle_periods:

        features["Idle Mean"] = np.mean(idle_periods)

        features["Idle Std"] = (
            np.std(idle_periods)
            if len(idle_periods) > 1
            else 0
        )

        features["Idle Max"] = max(idle_periods)

        features["Idle Min"] = min(idle_periods)

    else:

        features["Idle Mean"] = 0
        features["Idle Std"] = 0
        features["Idle Max"] = 0
        features["Idle Min"] = 0

    return features

def calculate_all_features(flow):

    features = {}

    features.update(
        calculate_basic_features(flow)
    )

    features.update(
        calculate_timing_features(flow)
    )

    features.update(
        calculate_flag_features(flow)
    )

    features.update(
        calculate_packet_features(flow)
    )

    features.update(
        calculate_bulk_subflow_features(flow)
    )

    features.update(
        calculate_active_idle_features(flow)
    )

    return features

if __name__ == "__main__":

    print("Starting packet capture...")

    sniff(
        prn=process_packet,
        count=100
    )

    print("\nCapture finished.")
    print("Total flows:", len(flows))

    # -------------------------------------------------
    # CSV OUTPUT
    # -------------------------------------------------

    feature_names = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Header Length.1",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min"
    ]

    print("\nFlow details:")

    captured_features = []

    for i, flow in enumerate(flows.values(), start=1):

        print(f"\nFlow {i}")

        print(
            "Source:",
            flow["source_ip"],
            ":",
            flow["source_port"]
        )

        print(
            "Destination:",
            flow["destination_ip"],
            ":",
            flow["destination_port"]
        )

        print("Protocol:", flow["protocol"])

        print("Total packets:", len(flow["packets"]))
        print("Forward packets:", len(flow["fwd_packets"]))
        print("Backward packets:", len(flow["bwd_packets"]))

        print(
            "Forward bytes:",
            sum(flow["fwd_packets"])
        )

        print(
            "Backward bytes:",
            sum(flow["bwd_packets"])
        )

        features = calculate_all_features(flow)

        captured_features.append(features)

        print("Number of features:", len(features))

    print("\nChecking feature count...")

    for features in captured_features:

        missing = [
            feature
            for feature in feature_names
            if feature not in features
        ]

        extra = [
            feature
            for feature in features
            if feature not in feature_names
        ]

        print("Calculated features:", len(features))
        print("Expected features:", len(feature_names))

        print("Missing features:", missing)
        print("Extra features:", extra)

    with open("captured_flows.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(feature_names)

        for features in captured_features:

            row = [
                features.get(feature, 0)
                for feature in feature_names
            ]

            writer.writerow(row)

    print("\n78-feature CSV created.")