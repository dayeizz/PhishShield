from fastapi import FastAPI
from UrlData import UrlData
from API import get_prediction
from Utils import unshortenUrl, domainStatus
import pickle
import uvicorn
import traceback
from fastapi.middleware.cors import CORSMiddleware
import json

# -----------------------------------------------------------------------------------

# FastAPI app for Phishing URL Detection

app = FastAPI(debug=True)

# -----------------------------------------------------------------------------------

# Enabling CORS policy

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------------

# Loading the the model

print("Loading the model...")
with open("xgb.pkl", "rb") as file:
    xgb = pickle.load(file)

# -----------------------------------------------------------------------------------

# Endpoint to receive a URL and return the prediction


@app.post("/predict")
def predict(data: UrlData):
    try:
        # --------------------------------------------------------------------

        # unshortening the URL and status code

        final_url = unshortenUrl(data.url)
        url = final_url.get("final_url")

        if final_url.get("status") == 403:
            msg = "Forbidden"
            print(msg)
            return {"message": msg}
        elif final_url.get("status") == 400:
            msg = "Bad request"
            print(msg)
            return {"message": msg}
        else:
            print("Final URL:", final_url.get("final_url"))

        # --------------------------------------------------------------------

        # validating URL status

        if not domainStatus(url):
            msg = "The URL is not valid or does not exist"
            print(msg)
            return {"message": msg}
        else:
            print("A Valid URL:", url)

        # --------------------------------------------------------------------

        # Prediction starts

        prediction = get_prediction(url, xgb, data.url)

        # --------------------------------------------------------------------

        # strealize the prediction data into json file

        msg = "Report in JSON file"
        data = {"message": msg, "predicted_probability": prediction}
        with open("report.json", "w") as json_file:
            json.dump(data, json_file, indent=4)

        print("JSON file saved successfully!")

        # --------------------------------------------------------------------

        # Returns message and prediction data

        return {"message": msg, "predicted_probability": prediction}
    except Exception as e:
        traceback.print_exc()
        return {"error": "An error occurred while processing the request."}


# -----------------------------------------------------------------------------------

# Endpoint to return the phishing prediction for details report


@app.post("/prediction")
async def prediction():

    # -----------------------------------------

    # Read JSON data from the file

    with open("report.json", "r") as file:
        data = json.load(file)
    print("data", data)
    return data


# -----------------------------------------------------------------------------------

# Run the FastAPI application using Uvicorn server

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
