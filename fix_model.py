import joblib

print("Loading model...")
model = joblib.load("phishing_model.pkl")

print("Saving model again...")
joblib.dump(model, "phishing_model.pkl")

print("Model re-saved successfully")