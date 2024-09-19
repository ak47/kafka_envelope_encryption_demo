"""
Usage: Python code to demonstrate the implementation on Envelope Encryption using AWS KMS
Before running this code, configure AWS Credentials in your environment:

$ export AWS_ACCESS_KEY_ID=<Your Access KEY ID>
$ export AWS_SECRET_ACCESS_KEY=<Your Secret Access Key>

Written on Dec/28/2022
"""

# Importing required libraries
import boto3
from botocore.exceptions import ClientError
from logging import getLogger
from os import urandom
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import base64
import json

# Setting the region
region = "us-west-1"

getLogger().setLevel("INFO")
getLogger("botocore").setLevel("CRITICAL")
getLogger("boto3").setLevel("CRITICAL")

# Create the KMS client
kms_client = boto3.client("kms", region_name=region)

# AWS CMK Key ARN
KEY_ID = "<Your Key ARN>"
TOPIC = "envelope_encryption_demo"
DATA_ENCRYPTION_KEY_GENERATOR = "OPENSSL"

def encrypt_data(plaintext, key_id):
    """
    Method to encrypt the data using envelope encryption
    The method returns encrypted data, encrypted data key, and also respective base64 encoded values.
    """
    # Generate a random IV
    iv = urandom(16)
    plaintext_data_key: bytes
    try:
        if DATA_ENCRYPTION_KEY_GENERATOR == "KMS":
            # Generate a data key using AWS KMS
            data_key = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
            plaintext_data_key = data_key["Plaintext"]
        elif DATA_ENCRYPTION_KEY_GENERATOR == "OPENSSL":
            # Generate a data key using OpenSSL
            plaintext_data_key = secrets.token_bytes(32)

            # encrypt the data key with AWS KMS
            data_key: dict = kms_client.encrypt(
                KeyId=key_id, Plaintext=plaintext_data_key
            )
    except ClientError as e:
        getLogger().error(e)
        exit()


    # Encrypt the data with AES CBC mode

    encrypted_data_key = data_key["CiphertextBlob"]
    cipher = Cipher(algorithms.AES(plaintext_data_key), modes.GCM(iv))
    encryptor = cipher.encryptor()


    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()

    ciphertext_blob = encryptor.update(padded_data) + encryptor.finalize()

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
        encryptor.tag,
    )


def decrypt_data(encoded_ciphertext_blob: bytes, encoded_encrypted_data_key: bytes, iv: bytes, gcm_tag: bytes) -> bytes:
    """
    Method to decrypt the data
    The method returns the decrypted data
    """
    # Base64 decode of encrypted data and encrypted data key
    decoded_ciphertext_blob: bytes = base64.b64decode(encoded_ciphertext_blob)
    decoded_encrypted_data_key: bytes = base64.b64decode(encoded_encrypted_data_key)

    # Decrypt the data key
    data_key: dict = kms_client.decrypt(CiphertextBlob=decoded_encrypted_data_key)
    plaintext_data_key: bytes = data_key["Plaintext"]

    # Decrypt the data
    cipher = Cipher(algorithms.AES(plaintext_data_key), modes.GCM(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data: bytes = decryptor.update(decoded_ciphertext_blob) + decryptor.finalize_with_tag(gcm_tag)

    unpadder = padding.PKCS7(128).unpadder()
    plaintext: bytes = unpadder.update(decrypted_padded_data)
    plaintext += unpadder.finalize()

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
        gcm_tag
    ) = encrypt_data(input_plaintext, KEY_ID)

    print(encoded_ciphertext_blob)
    # Decrypt the data
    plaintext = decrypt_data(encoded_ciphertext_blob, encoded_encrypted_data_key, iv, gcm_tag)
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
