from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

# Load model and vectorizer
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# ✅ Home route (for testing)
@app.route("/")
def home():
    return "Fake News Detection API is running!"

# ✅ Prediction route (used by PHP)
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        text = data.get("text", "")

        if not text:
            return jsonify({"error": "No text provided"}), 400

        # Transform and predict
        vect = vectorizer.transform([text])
        prediction = model.predict(vect)[0]

        # Convert result to expected format
        if prediction == 0:
            verdict = "fake"
            label = "Fake News"
            confidence = 0.85   # you can improve later
        else:
            verdict = "real"
            label = "Real News"
            confidence = 0.90

        return jsonify({
            "verdict": verdict,
            "confidence": confidence,
            "label": label
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Run server
if __name__ == "__main__":
    app.run(debug=True, port=5000)