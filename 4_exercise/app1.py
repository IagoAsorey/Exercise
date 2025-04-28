import socket, json, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import main

def run():
    # Configuración de conexión usando variables de entorno
    host = os.getenv('APP_HOST', 'localhost')
    port = int(os.getenv('APP2_PORT', 5001))

    private_key = rsa.generate_private_key(     # Generación de claves RSA
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()       # Clave pública derivada

    message = input("Enter message to sign: ").encode('utf-8')  # Entrada del mensaje a firmar
    
    signature = private_key.sign(               # Firma digital usando clave privada
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = base64.b64encode(signature).decode('utf-8') # Codificación de la firma en base64
    
    public_pem = public_key.public_bytes(       # Serialización de la clave pública a formato PEM
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    data = {                                    # Empaquetado de datos para enviar
        "message": message.decode('utf-8'),
        "signature": signature_b64,
        "public_key": public_pem
    }
    
    json_data = json.dumps(data)                # Conversión a JSON
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    # Envio por socket a app2
        s.connect((host, port))
        s.sendall(json_data.encode('utf-8'))
        with main.print_lock:
            print("\nData sent to Application 2 (Tampering Proxy).")
