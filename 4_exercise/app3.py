import socket
import json
import base64
import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import main

def run():
    # Configuración de conexión usando variables de entorno
    host = os.getenv("APP_HOST", "localhost")
    port = int(os.getenv("APP3_PORT", 5002))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        with main.print_lock:
            print(f"Application 3 (Verifier) listening on {host}:{port}\n")
        conn, addr = s.accept()                 # Aceptar conexión de app2

        with conn:
            time.sleep(1)
            with main.print_lock:
                print("App3 Connected by", addr)
            
            data = b''                          # Recepción robusta de datos
            while True:
                chunk = conn.recv(4096)         # Recibe bloques de 4kb
                if not chunk:
                    break
                data += chunk

            if not data:
                return
            
            try:
                received_data = json.loads(data.decode("utf-8"))    # Decodificación de JSON
            except json.JSONDecodeError:
                with main.print_lock:
                    print("Error decoding JSON:")
                return
            
            # Preparación de datos para verificación
            message = received_data["message"].encode("utf-8")
            signature_b64 = received_data["signature"]

            try:
                signature = base64.b64decode(signature_b64)         # Decodificación de la firma
            except Exception as e:
                with main.print_lock:
                    print("Error:", str(e))
                return
            
            # Carga de la clave pública desde PEM
            public_key_pem = received_data["public_key"].encode("utf-8")
            try:
                public_key = serialization.load_pem_public_key(public_key_pem)
            except (ValueError, TypeError) as e:
                with main.print_lock:
                    print("Error loading public key:", str(e))
                return
                          
            try:
                public_key.verify(          # Verificación de la firma
                    signature,
                    message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                with main.print_lock:
                    print("Signature is VALID.")
            except Exception as e:
                with main.print_lock:
                    print("Signature is INVALID.")
                    print("Verification error:", str(e))
