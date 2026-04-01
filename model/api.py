from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

model = pickle.load(open("model.pkl","rb"))
vectorizer = pickle.load(open("vectorizer.pkl","rb"))

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json["text"]
    vect = vectorizer.transform([data])
    result = model.predict(vect)[0]

    return jsonify({"result": int(result)})

app.run(port=5000)
