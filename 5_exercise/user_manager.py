import os, csv, base64
from config import CREDENTIALS_FILE, USERS_SIZE, DATA_FILE
import security, storage

# Verifica si un usuario ya está registrado
def user_exists(username: str) -> bool:
    if not os.path.exists(CREDENTIALS_FILE):
        return False
    with open(CREDENTIALS_FILE, 'r', newline='', encoding='utf-8') as file:
        return any(row['username'] == username for row in csv.DictReader(file))

# Registra un nuevo usuario
def register_user(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Username or password invalid")
    if user_exists(username):
        raise ValueError("Username already exists")

    # Generar salt y derivar clave
    salt = os.urandom(USERS_SIZE)
    derived_key = security.derive_key(password, salt)

    # Preparar datos para almacenamiento
    user_data = {
        'username': username,
        'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),
        'hash': base64.urlsafe_b64encode(derived_key).decode('utf-8')
    }

    # Asegurar que el directorio y archivo existan
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    storage.init_file(CREDENTIALS_FILE, header=['username', 'salt', 'hash'])

    # Escribir datos en el archivo
    with open(CREDENTIALS_FILE, 'a', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=['username', 'salt', 'hash'])
        if os.stat(CREDENTIALS_FILE).st_size == 0:
            writer.writeheader()
        writer.writerow(user_data)

    # Crear archivo de datos cifrado vacío
    storage.save_entries(username, [])
    return True

# Verifica usuario/contraseña
def authenticate_user(username: str, password: str) -> bool:
    if not os.path.exists(CREDENTIALS_FILE):
        return False

    try:
        # Leer datos del usuario
        with open(CREDENTIALS_FILE, 'r', newline='', encoding='utf-8') as file:
            user_data = next((row for row in csv.DictReader(file) if row['username'] == username), None)
        if not user_data:
            return False

        # Recuperar salt y verificar hash
        salt = base64.urlsafe_b64decode(user_data['salt'])
        stored_hash = user_data['hash'].encode('utf-8')
        derived_key = security.derive_key(password, salt)
        return base64.urlsafe_b64encode(derived_key) == stored_hash

    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return False