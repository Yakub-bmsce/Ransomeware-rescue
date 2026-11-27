import os

from models.incident import Incident
from flask_jwt_extended import JWTManager
from routes.files import files_bp
from models.file import File
from routes.auth import auth_bp
from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from extensions import db
from models.user import User

app = Flask(__name__)

app.config.from_object(Config)
jwt = JWTManager(app)

os.makedirs(app.instance_path, exist_ok=True)

CORS(app)

db.init_app(app)
app.register_blueprint(auth_bp)
app.register_blueprint(files_bp)

# Create database tables
with app.app_context():
    db.create_all()


@app.route("/")
def home():

    return jsonify({
        "message": "Ransomware Rescue Backend Running!",
        "status": "Success"
    })


@app.route("/api/health")
def health():

    return jsonify({
        "success": True,
        "message": "Backend is healthy"
    })


@app.route("/api/db-check")
def database_check():

    total_users = User.query.count()

    return jsonify({
        "success": True,
        "database": "Connected",
        "total_users": total_users
    })


if __name__ == "__main__":

    app.run(debug=True)