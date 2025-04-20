import os, csv
from typing import List, Dict
from cryptography.fernet import Fernet
from user_manag import DATA_FILENAME
from security import decrypt_data, encrypt_data

# Carga el nombre del archivo de datos del usuario
def get_data_filename(username: str) -> str:
    return DATA_FILENAME.format(username=username)

# Carga las entradas cifradas desde el archivo
def load_entries(fernet: Fernet, username: str) -> list:
    filename = get_data_filename(username)
    if not os.path.exists(filename):
        return []
    
    try:
        with open(filename, 'rb') as file:
            encrypted_data = file.read()
            decrypted_data = decrypt_data(fernet, encrypted_data)
            
            if not decrypted_data:
                return []
                
            return list(csv.DictReader(decrypted_data.decode('utf-8').splitlines()))
    except Exception as e:
        print(f"Error cargando datos: {str(e)}")
        return []

# Guarda las entradas cifradas en el archivo
def save_entries(fernet: Fernet, username: str, entries: list):
    filename = get_data_filename(username)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    fieldnames = ['Title', 'EncryptedPassword', 'URL', 'Notes']
    
    try:
        from io import StringIO
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                'Title': entry.get('Title', ''),
                'EncryptedPassword': entry.get('EncryptedPassword', ''),
                'URL': entry.get('URL', ''),
                'Notes': entry.get('Notes', '')
            })

        data = output.getvalue().encode('utf-8')
        encrypted = encrypt_data(fernet, data)
        if encrypted is None:
            raise ValueError("Encryption failed")
        
        with open(filename, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        print(f"Error guardando datos: {str(e)}")
