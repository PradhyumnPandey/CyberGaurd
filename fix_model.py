import joblib

print("Loading model...")
model = joblib.load("phishing_model.pkl")

print("Re-saving model...")
joblib.dump(model, "phishing_model.pkl")

print("Model fixed successfully.")