import base64, csv
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from user_manag import CREDENTIALS_FILE, KDF_ITERATIONS

# Inicializa el cifrado Fernet con la contraseña maestra
def initialize_encryption(username: str, master_password: str) -> Fernet:
    try:
        with open(CREDENTIALS_FILE, 'r', newline='', encoding='utf-8') as file:
            user_data = next(
                (row for row in csv.DictReader(file) if row['username'] == username),
                None
            )
            
        if not user_data:
            raise ValueError("User not registered")
            
        salt = base64.urlsafe_b64decode(user_data['salt'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
            backend=default_backend()
        )
        
        derived_key = kdf.derive(master_password.encode())
        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)
        
    except (FileNotFoundError, KeyError) as e:
        raise ValueError("Error in the credentials file") from e

# Cifra los datos proporcionados
def encrypt_data(fernet: Fernet, data: bytes) -> bytes:
    try:
        return fernet.encrypt(data)
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

# Descifra los datos proporcionados
def decrypt_data(fernet: Fernet, data: bytes) -> bytes:
    try:
        return fernet.decrypt(data)
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None