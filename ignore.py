import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def millis() -> int:
    return round(time.time() * 1000)


def gen_kdf(salt: bytes, ittr: int) -> PBKDF2HMAC:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=ittr,
        backend=default_backend()
    )

    return kdf


SALT = b'\xeb\x01\x8e\xc1\xc4T8Q\x1d\xa9.I\xc8\xfa\x05$'
MATT = b'\xff\x8f\xdd\xc2_9\\\xcf\xe6>K\x00!48N'


if __name__ == '__main__':
    for ittr in [1, 1024, 4096, 10000, 100000, 250000, 500000, 1000000]:
        start = millis()
        kdf = gen_kdf(SALT, ittr)
        kdf.derive(MATT)
        print(f'[ittr: {ittr} \t|\t time: {millis() - start}]')
        time.sleep(1)
