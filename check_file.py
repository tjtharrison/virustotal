import argparse
import asyncio
import itertools
import hashlib
import os
import sys
import requests

from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("VIRUS_TOTAL_API_KEY")

def get_file_hash(file_path):
    """Gets the hash of a file.

    Args:
        file_path: The path to the file.

    Returns:
        The hash of the file.
    """
    with open(file_path, "rb") as file:
        # Use hashlib to get SHA-1 for the file
        file_hash = hashlib.sha1()
        while True:
            # Read file in as little chunks
            chunk = file.read(4096)
            if not chunk:
                break
        file_hash.update(chunk)

    return file_hash.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_file.py <file_path>")
        sys.exit(1)

    try:
        file_hash = get_file_hash(sys.argv[1])
    except IOError:
        print("Error reading file " + sys.argv[1])
        sys.exit(1)

    print(file_hash)

    # Search VirusTotal for the file
    try:
        response = requests.get(
            "https://www.virustotal.com/api/v3/files/" + file_hash,
            headers={"x-apikey": api_key},
        )
    except requests.exceptions.RequestException as e:
        print("Error: " + str(e))
        sys.exit(1)

    # print(response.json())