from fastapi import FastAPI
import pandas as pd
from pathlib import Path
from model import predict
from schemas import PredictionRequest


app = FastAPI()


@app.get("/")
def home():
    return {
        "message": "SIH26145 Backend is running"
    }


@app.post("/predict")
def make_prediction(request: PredictionRequest):

    data = pd.DataFrame([request.features])

    result = predict(data)

    return {
        "prediction": result
    }
    
@app.get("/test-predict")
def test_prediction():

    file_path = (
        Path(__file__).resolve().parent.parent
        / "MLmodel"
        / "Dataset"
        / "Raw"
        / "MachineLearningCSV"
        / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    data = pd.read_csv(file_path)

    data.columns = data.columns.str.strip()

    sample = data[data["Label"] == "DDoS"].iloc[[0]]

    X = sample.drop("Label", axis=1)

    result = predict(X)

    return {
        "prediction": result
    }