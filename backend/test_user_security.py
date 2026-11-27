import requests

BASE_URL = "http://127.0.0.1:5000"

# Register another student
register_data = {
    "name": "Student Two",
    "email": "student2@test.com",
    "password": "Student12345"
}

register_response = requests.post(
    f"{BASE_URL}/api/auth/register",
    json=register_data
)

print("Registration:", register_response.status_code)

# Login as Student Two
login_data = {
    "email": "student2@test.com",
    "password": "Student12345"
}

login_response = requests.post(
    f"{BASE_URL}/api/auth/login",
    json=login_data
)

token = login_response.json()["access_token"]

headers = {
    "Authorization": f"Bearer {token}"
}

# Try accessing Student One's file
FILE_ID = 1  # Replace with Student One's actual file ID

url = f"{BASE_URL}/api/files/{FILE_ID}/download"

response = requests.get(url, headers=headers)

print("Access Status:", response.status_code)
print("Access Result:", response.text)