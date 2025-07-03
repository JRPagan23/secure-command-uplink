import os
import json
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import urlsafe_b64encode, urlsafe_b64decode

def load_key(path):
    with open(path, "rb") as f:
        key = f.read().strip()
        try:
            key_bytes = urlsafe_b64decode(key)
        except Exception as e:
            raise ValueError(f"Invalid key encoding: {e}")
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES key must be 128, 192, or 256 bits.")
        return key_bytes

def encrypt(command, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    message_dict = {
        "command": command,
        "timestamp": time.time()
    }
    plaintext = json.dumps(message_dict).encode()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # HMAC for integrity
    hmac_tag = hmac.new(key, ciphertext, hashlib.sha256).digest()

    return json.dumps({
        "nonce": urlsafe_b64encode(nonce).decode(),
        "ciphertext": urlsafe_b64encode(ciphertext).decode(),
        "hmac": urlsafe_b64encode(hmac_tag).decode()
    }).encode()

def decrypt(payload, key):
    try:
        message = json.loads(payload)
        nonce = urlsafe_b64decode(message["nonce"])
        ciphertext = urlsafe_b64decode(message["ciphertext"])
        received_hmac = urlsafe_b64decode(message["hmac"])
    except Exception as e:
        raise ValueError(f"Invalid message format: {e}")

    expected_hmac = hmac.new(key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("HMAC verification failed.")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)

def verify_hmac(ciphertext, received_hmac, key):
    expected_hmac = hmac.new(key, ciphertext, hashlib.sha256).digest()
    return hmac.compare_digest(expected_hmac, received_hmac)
