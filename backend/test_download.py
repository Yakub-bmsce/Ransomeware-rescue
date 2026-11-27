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

# Get my files
files_url = "http://127.0.0.1:5000/api/files/my-files"

files_response = requests.get(files_url, headers=headers)

print("My Files:", files_response.json())

# Get the first file ID
files = files_response.json()["files"]

if files:
    file_id = files[0]["file_id"]

    # Download that file
    download_url = f"http://127.0.0.1:5000/api/files/{file_id}/download"

    response = requests.get(download_url, headers=headers)

    print("Download Status:", response.status_code)

    if response.status_code == 200:
        with open("downloaded_file.txt", "wb") as file:
            file.write(response.content)

        print("File downloaded successfully!")

else:
    print("No files found. Upload a file first.")