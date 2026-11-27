import requests

# Login
login_url = "http://127.0.0.1:5000/api/auth/login"

login_data = {
    "email": "yakub@test.com",
    "password": "Yakub12345"
}

login_response = requests.post(login_url, json=login_data)

token = login_response.json()["access_token"]

headers = {
    "Authorization": f"Bearer {token}"
}

# Get incident history
url = "http://127.0.0.1:5000/api/incidents/my-incidents"

response = requests.get(url, headers=headers)

print("Status Code:", response.status_code)
print("Incident History:", response.json())