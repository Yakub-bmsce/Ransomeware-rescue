from datetime import datetime, timezone
from extensions import db


class File(db.Model):

    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    file_path = db.Column(
        db.String(500),
        nullable=False
    )

    sha256_hash = db.Column(
        db.String(64),
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )