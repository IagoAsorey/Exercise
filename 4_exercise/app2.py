import socket, json, base64, os, time

import main

def run():
    # Configuración de conexión usando variables de entorno
    host = os.getenv('APP_HOST', 'localhost')
    port = int(os.getenv('APP2_PORT', 5001))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        with main.print_lock:
            print(f"Application 2 (Tampering Proxy) listening on {host}:{port}\n")
        conn, addr = s.accept()                 # Aceptar conexión de app1
    
        with conn:
            time.sleep(1)
            with main.print_lock:
                print("App2 Connected by", addr)
            
            data = b''                          # Recepción robusta de datos
            while True:
                chunk = conn.recv(4096)         # Recibe bloques de 4kb
                if not chunk:
                    break
                data += chunk

            if not data:
                return
            
            try:
                received_data = json.loads(data.decode('utf-8'))    # Decodificación de JSON
            except json.JSONDecodeError:
                with main.print_lock:
                    print("Error decoding JSON:")
                return
            
            with main.print_lock:               # Muestra resumen de datos
                print("\n--- Application 2 Received Data ---")
                print("Message:", received_data['message'])
                print("Signature:", received_data['signature'])
                print("Public Key:", received_data['public_key'][:50] + "...\n")
              
            # Permite al usuario modificar la firma
            new_sig = input("Enter modified signature (press Enter to keep unchanged): ")
            if new_sig.strip():
                try:
                    base64.b64decode(new_sig, validate=True)        # Valida de base64
                    received_data["signature"] = new_sig.strip()
                    with main.print_lock:
                        print("Signature has been modified.")
                except:
                    with main.print_lock:
                        print("Invalid base64. Signature not modified.")
            else:
                with main.print_lock:
                    print("Signature has not been modified.")
              
            forward(received_data)           # Envía datos a app3

def forward(data):
    # Configuración para enviar a app3
    host = os.getenv('APP_HOST', 'localhost')
    port = int(os.getenv('APP3_PORT', 5002))
    json_data = json.dumps(data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    # Envio por socket a app3
        s.connect((host, port))
        s.sendall(json_data.encode('utf-8'))
        with main.print_lock:
            print("\nData sent to Application 3 (Verifier).")
