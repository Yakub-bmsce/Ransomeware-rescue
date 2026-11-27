
from models.incident import Incident
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import Blueprint, request, jsonify, send_file, current_app 
from werkzeug.utils import secure_filename
from extensions import db
from models.file import File
import hashlib
import os
import uuid

files_bp = Blueprint("files", __name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")


@files_bp.route("/api/files/upload", methods=["POST"])
@jwt_required()
def upload_file():
    user_id = int(get_jwt_identity())

    if "file" not in request.files:
        return jsonify({
            "success": False,
            "message": "No file provided"
        }), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({
            "success": False,
            "message": "No file selected"
        }), 400

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        return jsonify({
            "success": False,
            "message": "Invalid filename"
        }), 400

    stored_filename = str(uuid.uuid4()) + "_" + original_filename

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    file_hash = hashlib.sha256()

    try:
        with open(file_path, "wb") as destination:
            while True:
                chunk = uploaded_file.stream.read(1024 * 1024)

                if not chunk:
                    break

                file_hash.update(chunk)
                destination.write(chunk)

        sha256_hash = file_hash.hexdigest()

        new_file = File(
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_path=file_path,
            sha256_hash=sha256_hash,
            user_id=int(user_id)
        )

        db.session.add(new_file)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "File uploaded successfully",
            "file_id": new_file.id,
            "filename": original_filename,
            "sha256_hash": sha256_hash
        }), 201

    # except Exception:
    #     if os.path.exists(file_path):
    #         os.remove(file_path)

    #     db.session.rollback()

    #     return jsonify({
    #         "success": False,
    #         "message": "File upload failed"
    #     }), 500 

    except Exception as e:
        print("UPLOAD ERROR:", str(e))

    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.rollback()

    return jsonify({
        "success": False,
        "message": "File upload failed"
    }), 500


@files_bp.route("/api/files/<int:file_id>/verify", methods=["GET"])
@jwt_required()
def verify_file(file_id):

    user_id = int(get_jwt_identity())

    file_record = File.query.filter_by(
        id=file_id,
        user_id=user_id
    ).first()

    if not file_record:
        return jsonify({
            "success": False,
            "message": "File not found"
        }), 404

    if not os.path.exists(file_record.file_path):
        return jsonify({
            "success": False,
            "message": "File is missing"
        }), 404

    current_hash = hashlib.sha256()

    with open(file_record.file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            current_hash.update(chunk)

    current_hash = current_hash.hexdigest()

    # Compare original and current hashes
    if current_hash == file_record.sha256_hash:

        return jsonify({
            "success": True,
            "integrity": "Verified",
            "message": "File is safe and unchanged"
        }), 200

    else:

        # Create an incident record
        new_incident = Incident(
            user_id=user_id,
            file_id=file_record.id,
            event_type="File Modification Detected",
            description="File hash mismatch detected during verification",
            status="Detected"
        )

        db.session.add(new_incident)
        db.session.commit()

        current_app.logger.warning(
            "FILE_INTEGRITY_MISMATCH user_id=%s file_id=%s incident_id=%s",
            user_id,
            file_record.id,
            new_incident.id
        )

        return jsonify({
            "success": True,
            "integrity": "Compromised",
            "message": "File modification detected!",
            "incident_id": new_incident.id
        }), 200


@files_bp.route("/api/files/my-files", methods=["GET"])
@jwt_required()
def get_my_files():

    user_id = int(get_jwt_identity())

    files = File.query.filter_by(user_id=user_id).all()

    file_list = []

    for file in files:
        file_list.append({
            "file_id": file.id,
            "filename": file.original_filename,
            "sha256_hash": file.sha256_hash,
            "uploaded_at": file.uploaded_at.isoformat()
        })

    return jsonify({
        "success": True,
        "files": file_list
    }), 200 

@files_bp.route("/api/files/<int:file_id>/download", methods=["GET"])
@jwt_required()
def download_file(file_id):

    # Identify the logged-in student
    user_id = int(get_jwt_identity())

    # Check whether this file belongs to this student
    file_record = File.query.filter_by(
        id=file_id,
        user_id=user_id
    ).first()

    if not file_record:
        return jsonify({
            "success": False,
            "message": "File not found"
        }), 404

    # Check whether the actual file exists
    if not os.path.exists(file_record.file_path):
        return jsonify({
            "success": False,
            "message": "File is missing from storage"
        }), 404

    # Send the file to the student
    return send_file(
        file_record.file_path,
        as_attachment=True,
        download_name=file_record.original_filename
    )


@files_bp.route("/api/incidents/my-incidents", methods=["GET"])
@jwt_required()
def get_my_incidents():

    user_id = int(get_jwt_identity())

    incidents = Incident.query.filter_by(
        user_id=user_id
    ).order_by(Incident.detected_at.desc()).all()

    incident_list = []

    for incident in incidents:
        incident_list.append({
            "incident_id": incident.id,
            "file_id": incident.file_id,
            "event_type": incident.event_type,
            "description": incident.description,
            "detected_at": incident.detected_at.isoformat(),
            "status": incident.status
        })

    return jsonify({
        "success": True,
        "total_incidents": len(incident_list),
        "incidents": incident_list
    }), 200