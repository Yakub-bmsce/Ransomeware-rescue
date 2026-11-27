import requests

# Step 1: Login
login_url = "http://127.0.0.1:5000/api/auth/login"

login_data = {
    "email": "yakub@test.com",
    "password": "Yakub12345"
}

login_response = requests.post(login_url, json=login_data)

token = login_response.json()["access_token"]

# Step 2: Prepare authentication
headers = {
    "Authorization": f"Bearer {token}"
}

# Step 3: Verify uploaded file
file_id = 1

verify_url = f"http://127.0.0.1:5000/api/files/{file_id}/verify"

response = requests.get(verify_url, headers=headers)

print("Verification Status:", response.status_code)
print("Verification Result:", response.json())