import os

from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding

pem = 'C:\\Users\\4ronse\\Desktop\\key.pem'

private_key = None

if os.path.exists(pem):
    with open(pem, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
else:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    pr_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(pem, 'wb') as key_file:
        key_file.write(pr_pem)

public_key = private_key.public_key()

encrypted = public_key.encrypt(input('Input> ').encode(), padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
))

decrypted = private_key.decrypt(encrypted, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
))

print(len(encrypted), urlsafe_b64encode(encrypted))
print(decrypted)
