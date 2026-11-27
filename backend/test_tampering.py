import os
import shutil
import hashlib

from app import app
from models.file import File

with app.app_context():

    # Get the uploaded file
    file_record = File.query.get(1)

    if not file_record:
        print("File not found!")
        exit()

    original_path = file_record.file_path

    # Create a separate simulation folder
    os.makedirs("simulation", exist_ok=True)

    modified_path = os.path.join(
        "simulation",
        "modified_copy.txt"
    )

    # Copy the original document
    shutil.copy2(original_path, modified_path)

    print("Original document copied successfully!")

    # Simulate unauthorized modification
    with open(modified_path, "a") as file:
        file.write("\nThis content was added without permission!")

    print("Simulation: Document modified!")

    # Calculate the modified file's hash
    with open(modified_path, "rb") as file:
        current_hash = hashlib.sha256(file.read()).hexdigest()

    # Compare hashes
    if current_hash == file_record.sha256_hash:
        print("File is unchanged!")
    else:
        print("WARNING: File modification detected!")
        print("Original Hash:", file_record.sha256_hash)
        print("Modified Hash:", current_hash)