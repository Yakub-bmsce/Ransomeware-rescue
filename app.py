from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

@app.route("/")
def home():
    return jsonify({
        "message": "Ransomware Rescue Backend is Running!",
        "status": "Success"
    })

@app.route("/api/health")
def health():
    return jsonify({
        "success": True,
        "message": "Backend is healthy"
    })

if __name__ == "__main__":
    app.run(debug=True)