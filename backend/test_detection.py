import requests
from pathlib import Path
from app import app
from models.file import File

BASE_URL = "http://127.0.0.1:5000"

# 1. Login
login_response = requests.post(
    f"{BASE_URL}/api/auth/login",
    json={
        "email": "yakub@test.com",
        "password": "Yakub12345"
    }
)

token = login_response.json()["access_token"]

headers = {
    "Authorization": f"Bearer {token}"
}

# 2. Select your uploaded file
FILE_ID = 1  # Change this to your actual file ID

# 3. Temporarily modify the stored file
with app.app_context():

    record = File.query.filter_by(id=FILE_ID).first()

    if not record:
        print("File not found!")
        raise SystemExit

    file_path = Path(record.file_path)
    original_content = file_path.read_bytes()

    try:
        file_path.write_bytes(
            original_content + b"\nUnauthorized test modification!"
        )

        print("Test modification completed!")

        # 4. Verify the file through the API
        response = requests.get(
            f"{BASE_URL}/api/files/{FILE_ID}/verify",
            headers=headers
        )

        print("Detection Status:", response.status_code)
        print("Detection Result:", response.json())

    finally:
        # 5. Restore original content
        file_path.write_bytes(original_content)
        print("Original file restored!")
