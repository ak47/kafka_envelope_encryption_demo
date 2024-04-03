"""
Usage: Python code to demonstrate the implementation on Envelope Encryption using AWS KMS
Before running this code, configure AWS Credentials in your environment:

$ export AWS_ACCESS_KEY_ID=<Your Access KEY ID>
$ export AWS_SECRET_ACCESS_KEY=<Your Secret Access Key>

Written on Dec/28/2022
"""

# Importing required libraries
import boto3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

# Setting the region
region = "us-east-1"

# Create the KMS client
kms_client = boto3.client("kms", region_name=region)

# AWS CMK Key ARN
KEY_ID = "< your key here >"
TOPIC = "envelope_encryption_demo"

def encrypt_data(plaintext, key_id):
    """
    Method to encrypt the data using envelope encryption
    The method returns encrypted data, encrypted data key, and also respective base64 encoded values.
    """
    # Generate a data key using AWS CMK
    data_key = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    plaintext_data_key = data_key["Plaintext"]
    encrypted_data_key = data_key["CiphertextBlob"]

    # Generate a random IV
    iv = get_random_bytes(16)

    # Encrypt the data with AES CBC mode
    cipher = AES.new(plaintext_data_key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, 16)
    ciphertext_blob = cipher.encrypt(padded_data)

    # Encode the encrypted data and data key  with base64
    encoded_ciphertext_blob = base64.b64encode(ciphertext_blob)
    encoded_encrypted_data_key = base64.b64encode(encrypted_data_key)

    # Return the encrypted data and the encrypted data key
    return (
        ciphertext_blob,
        encoded_ciphertext_blob,
        encrypted_data_key,
        encoded_encrypted_data_key,
        iv,
    )


def decrypt_data(encoded_ciphertext_blob, encoded_encrypted_data_key, iv):
    """
    Method to decrypt the data
    The method returns the decrypted data
    """
    # Base64 decode of encrypted data and encrypted data key
    decoded_ciphertext_blob = base64.b64decode(encoded_ciphertext_blob)
    decoded_encrypted_data_key = base64.b64decode(encoded_encrypted_data_key)

    # Decrypt the data key
    data_key = kms_client.decrypt(CiphertextBlob=decoded_encrypted_data_key)
    plaintext_data_key = data_key["Plaintext"]

    # Decrypt the data
    cipher = AES.new(plaintext_data_key, AES.MODE_CBC, iv)
    decrypted_padded_data = cipher.decrypt(decoded_ciphertext_blob)
    plaintext = unpad(decrypted_padded_data, 16)

    # Return the decrypted data
    return plaintext


def main():
    """
    Main method
    """

    # Setting the plain text, which needs to be encrypted
    # input_plaintext = b"This is a confidential message which needs to be encrypted."
    input_plaintext = bytes(
        json.dumps(["foo", {"bar": ("baz", None, 1.0, 2)}]), "utf-8"
    )

    # Encrypting the data
    (
        ciphertext_blob,
        encoded_ciphertext_blob,
        encrypted_data_key,
        encoded_encrypted_data_key,
        iv,
    ) = encrypt_data(input_plaintext, KEY_ID)

    # Decrypt the data
    plaintext = decrypt_data(encoded_ciphertext_blob, encoded_encrypted_data_key, iv)
    print(json.loads(str(plaintext, "utf-8")))

    # Store the encrypted string and the encrypted data key in a file (optional)
    with open("datastore.csv", "w") as f:
        f.writelines(
            [
                str(encoded_ciphertext_blob) + ",",
                str(encoded_encrypted_data_key) + ",",
                str(iv),
            ]
        )


if __name__ == "__main__":
    main()
