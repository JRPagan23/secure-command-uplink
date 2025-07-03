import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
key_b64 = base64.urlsafe_b64encode(key).decode('utf-8')

with open('secret.key', 'w') as f:
    f.write(key_b64)

print("Secret key generated and saved to secret.key")
