
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from extensions import db
from models.user import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/api/auth/register", methods=["POST"])
def register():

    data = request.get_json()

    if not data:
        return jsonify({"success": False, "message": "Invalid request"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # Check empty fields
    if not name or not email or not password:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    # Check password length
    if len(password) < 8:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 8 characters"
        }), 400

    # Check existing email
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 409

    # Hash password
    hashed_password = generate_password_hash(password)

    # Create user
    new_user = User(
        name=name,
        email=email,
        password_hash=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Registration successful!"
    }), 201

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    if not check_password_hash(user.password_hash, password):
        return jsonify({
            "success": False,
            "message": "Incorrect password"
        }), 401

    token = create_access_token(identity=str(user.id))

    return jsonify({
        "success": True,
        "message": "Login successful",
        "access_token": token
    }), 200