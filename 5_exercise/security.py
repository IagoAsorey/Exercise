import base64, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import KDF_ITERATIONS, ENTRY_AES_KEY

# Decodifica la clave AES desde Base64 y valida su longitud
def get_AES_key(entry_key: str) -> AESGCM:
    key = base64.urlsafe_b64decode(entry_key + '=' * (-len(entry_key) % 4))
    if len(key) not in (16, 24, 32):
        raise ValueError("Decoded AES key must be 128, 192, or 256 bits.")
    return AESGCM(key)
aesgcm = get_AES_key(ENTRY_AES_KEY)

# Cifra los datos proporcionados
def encrypt_data(data: bytes, associated_data: bytes = None) -> bytes:
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, data, associated_data)
    return base64.urlsafe_b64encode(nonce + encrypted)

# Descifra los datos proporcionados
def decrypt_data(token: bytes, associated_data: bytes = None) -> bytes:
    raw = base64.urlsafe_b64decode(token)
    nonce, encrypted = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, encrypted, associated_data)

# Deriva una clave a partir de la contraseña y la sal
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())
