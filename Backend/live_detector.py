from scapy.all import sniff
import time
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "Datacapture"))

from capture import process_packet, flows
from services.flow_services import (
    check_completed_flows,
    process_completed_flow
)


print("Starting live detection...")


def process_finished_flows():

    completed_flows = check_completed_flows(flows)

    for flow_key, flow in completed_flows:

        prediction = process_completed_flow(flow)

        print(
            f"\nFlow detected: {prediction}"
        )

        del flows[flow_key]


while True:

    sniff(
        prn=process_packet,
        timeout=1
    )

    process_finished_flows()