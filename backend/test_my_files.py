import requests

# Login
login_url = "http://127.0.0.1:5000/api/auth/login"

login_data = {
    "email": "yakub@test.com",
    "password": "Yakub12345"
}

login_response = requests.post(login_url, json=login_data)

token = login_response.json()["access_token"]

# Authentication
headers = {
    "Authorization": f"Bearer {token}"
}

# Fetch my files
url = "http://127.0.0.1:5000/api/files/my-files"

response = requests.get(url, headers=headers)

print("Status Code:", response.status_code)
print("Response:", response.json())