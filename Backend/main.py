from fastapi import FastAPI, HTTPException
from services.predictor import predict_flow


app = FastAPI(
    title="SIH26145 Cyber Threat Detection API",
    description="AI-based detection of threats in unidirectional IP traffic",
    version="1.0.0"
)


@app.get("/")
def root():

    return {
        "message": "SIH26145 Backend is running"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


@app.post("/predict")
def predict(features: dict):

    try:

        prediction = predict_flow(features)

        return {
            "prediction": prediction
        }

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )