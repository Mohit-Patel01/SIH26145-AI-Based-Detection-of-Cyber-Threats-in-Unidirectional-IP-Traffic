import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "Datacapture"))

from capture import calculate_all_features
from services.predictor import predict_flow


FLOW_TIMEOUT = 5


def check_completed_flows(flows):

    completed_flows = []

    current_time = datetime.now()

    for flow_key, flow in list(flows.items()):

        idle_time = (
            current_time - flow["last_time"]
        ).total_seconds()

        if idle_time >= FLOW_TIMEOUT:

            completed_flows.append(
                (flow_key, flow)
            )

    return completed_flows


def process_completed_flow(flow):

    features = calculate_all_features(flow)

    prediction = predict_flow(features)

    return prediction