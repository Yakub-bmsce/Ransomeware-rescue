import os

class Config:

    SQLALCHEMY_DATABASE_URI = "sqlite:///student_vault.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.getenv("SECRET_KEY", "development-only-key")

    JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "temporary-development-jwt-key"
)

JWT_ACCESS_TOKEN_EXPIRES = 1800