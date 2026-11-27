import requests

url = "http://127.0.0.1:5000/api/auth/register"

data = {
    "name": "Yakub",
    "email": "yakub@test.com",
    "password": "Yakub12345"
}

response = requests.post(url, json=data)

print("Status Code:", response.status_code)
print("Response:", response.json())