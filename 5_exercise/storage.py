import os, csv, io
from config import DATA_FILE
import security

# Inicializa un archivo CSV con encabezados si no existe
def init_file(filepath: str, header: list = None) -> bool:
    if not os.path.exists(filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', newline='', encoding='utf-8') as file:
            if header:
                csv.writer(file).writerow(header)

# Guarda las entradas cifradas en el archivo
def save_entries(username: str, entries: list):
    filename = DATA_FILE.format(username=username)
    fieldnames = ['Title', 'EncryptedPassword', 'URL', 'Notes']
    
    try:
        # Filtra y preparar las entradas
        valid_entries = [{key: entry.get(key, '') for key in fieldnames} for entry in entries]

        # Escribir datos en momoria
        data = io.StringIO()
        writer = csv.DictWriter(data, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(valid_entries)
        
        # Cifrar y guardar en el archivo
        encrypted = security.encrypt_data(data.getvalue().encode('utf-8'))
        with open(filename, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        print(f"Error guardando datos: {str(e)}")

# Carga las entradas cifradas desde el archivo
def load_entries(username: str) -> list:
    filename = DATA_FILE.format(username=username)
    if not os.path.exists(filename):
        return []
    
    try:
        with open(filename, 'rb') as file:
            # Descifrar y leer el archivo
            data = security.decrypt_data(file.read())
            return list(csv.DictReader(data.decode('utf-8').splitlines()))
    except Exception as e:
        print(f"Error cargando datos: {str(e)}")
        return []
