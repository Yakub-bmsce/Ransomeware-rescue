import requests

# Step 1: Login
login_url = "http://127.0.0.1:5000/api/auth/login"

login_data = {
    "email": "yakub@test.com",
    "password": "Yakub12345"
}

login_response = requests.post(login_url, json=login_data)

token = login_response.json()["access_token"]

print("Login successful!")

# Step 2: Upload file with token
upload_url = "http://127.0.0.1:5000/api/files/upload"

headers = {
    "Authorization": f"Bearer {token}"
}

with open("sample.txt", "rb") as file:
    response = requests.post(
        upload_url,
        files={"file": file},
        headers=headers
    )

print("Upload Status:", response.status_code)
print("Upload Response:", response.json())