import os, csv, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constantes
DATA_FILENAME = "Users/{username}_data.enc"
CREDENTIALS_FILE = "Users/users.csv"
USERS_SIZE = 16
KDF_ITERATIONS = 100_000

# Crea un objeto KDF configurado con parámetros de seguridad
def create_kdf(salt: bytes) -> PBKDF2HMAC:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )

# verifica si un usuario ya esta registrado
def user_exists(username: str) -> bool:
    if not os.path.exists(CREDENTIALS_FILE):
        return False
        
    with open(CREDENTIALS_FILE, 'r', newline='', encoding='utf-8') as file:
        return any(row['username'] == username for row in csv.DictReader(file))

# Registra un nuevo usuario con PBKDF2 hashing y crea su archivo de datos vacío cifrado
def register_user(username: str, password: str):
    # Validación inicial
    if not username or not password:
        raise ValueError("User or password invalid")
    if user_exists(username):
        raise ValueError("User already exists")

    # Generar salt y derivar clave
    salt = os.urandom(USERS_SIZE)
    kdf = create_kdf(salt)
    derived_key = kdf.derive(password.encode())
    
    # Preparar datos para almacenamiento
    user_data = {
        'username': username,
        'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),
        'hash': base64.urlsafe_b64encode(derived_key).decode('utf-8')
    }

    # Escribir en archivo CSV
    file_exists = os.path.exists(CREDENTIALS_FILE)
    with open(CREDENTIALS_FILE, 'a', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=['username', 'salt', 'hash'])
        if not file_exists:
            writer.writeheader()
        writer.writerow(user_data)

    # Crear archivo de datos cifrado
    from security import initialize_encryption
    from storage import save_entries
    fernet = initialize_encryption(username, password)
    save_entries(fernet, username, [])

# Verifica usuario/contraseña usando PBKDF2 compare
def authenticate_user(username: str, password: str) -> bool:
    if not os.path.exists(CREDENTIALS_FILE):
        return False
    
    with open(CREDENTIALS_FILE, 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        user_data = next((row for row in reader if row['username'] == username), None)
        
    if not user_data:
        return False

    try:
        # Recuperar salt y verificar hash
        salt = base64.urlsafe_b64decode(user_data['salt'])
        stored_hash = user_data['hash'].encode('utf-8')
        
        kdf = create_kdf(salt)
        derived_key = kdf.derive(password.encode())
        generated_hash = base64.urlsafe_b64encode(derived_key)
        
        return generated_hash == stored_hash
        
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return False