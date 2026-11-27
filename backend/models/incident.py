from datetime import datetime, timezone
from extensions import db


class Incident(db.Model):

    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("files.id"),
        nullable=False
    )

    event_type = db.Column(db.String(100), nullable=False)

    description = db.Column(db.String(255), nullable=False)

    detected_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    status = db.Column(db.String(50), default="Detected")