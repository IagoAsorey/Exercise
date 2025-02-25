from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes    # Used for AES encryption
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os               # Generates random values
import base64           # Encodes and decodes encrypted data
import tkinter as tk    # Intefaces
from tkinter import messagebox

# AES Encryption/Decryption System
class AESSystem:
    def __init__(self, key, mode):      # Inicializa el istema AES con una key de 16 caracteres y un modo de encriptción
        self.key = key.encode('utf-8')
        self.mode = mode

    def encrypt(self, plaintext):       # Encripta
        plaintext = plaintext.encode('utf-8')   # Convierte texto a bytes
        padder = padding.PKCS7(128).padder()    # Añade padding para hacer el texto multiplo de 16
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        iv = os.urandom(16)         # Genera random IV para encriptar
        cipher = self.get_cipher(iv)   # Crea un cipher con el modo seleccionado
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()  # Encripta el texto padded
        return base64.b64encode(iv + ciphertext).decode('utf-8')        # Devuelve base64 encoded IV + texto cifrado

    def decrypt(self, ciphertext):      # Desencripta
        try:
            data = base64.b64decode(ciphertext)     # Decodifica base64-encoded a texto
            iv, actual_ciphertext = data[:16], data[16:]    # Extrae el IV y el texto cifrado
            
            cipher = self.get_cipher(iv)   # Inizializa el cipher con el IV extraido
            decryptor = cipher.decryptor()
            
            decrypted_padded_text = decryptor.update(actual_ciphertext) + decryptor.finalize()  # Desencripta el texto cifrado
            unpadder = padding.PKCS7(128).unpadder()        # Quita el padding y devuelve el texto
            return unpadder.update(decrypted_padded_text) + unpadder.finalize()
        except Exception:
            return "Decryption Error: Invalid key or corrupted data"

    def get_cipher(self, iv):      # Define los modos de cifrado
        mode_dict = {
            'ECB': modes.ECB(),   # No requiere IV
            'CBC': modes.CBC(iv),
            'CFB': modes.CFB(iv)
        }
        return Cipher(algorithms.AES(self.key), mode_dict[self.mode], backend=default_backend())

# File Operations
def save_file(content, filename="ciphertext.txt"):   # Guarda el texto encriptado a archivo
    with open(filename, "w") as f:
        f.write(content)

def load_file(filename="ciphertext.txt"):      # Carga el texto encriptado desde un archivo
    try:
        with open(filename, "r") as f:
            return f.read()
    except FileNotFoundError:
        return None

# GUI Functions
def set_mode(mode):     # Establece el modo de encriptado
    global selected_mode
    selected_mode = mode
    update_mode_buttons()

def update_mode_buttons():      # Marca el boton usado
    for btn in mode_buttons:
        btn.config(bg="gray" if btn["text"] == selected_mode else "lightgray")

def perform_action(action):     # Coge la key
    key = key_entry.get()
    if len(key) != 16:      # Valida la key
        messagebox.showerror("Error", "Key must be exactly 16 characters long")
        return
    
    aes = AESSystem(key, selected_mode)

    if action == "Encrypt":
        text = text_entry.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        result = aes.encrypt(text)
        save_file(result)
    else:
        ciphertext = load_file()
        if not ciphertext:
            messagebox.showerror("Error", "No encrypted file found")
            return
        result = aes.decrypt(ciphertext)
    
    # Muestra resultado
    result_entry.delete("1.0", "end")
    result_entry.insert("1.0", result)

# Tkinter GUI Setup
root = tk.Tk()
root.title("AES Encryption/Decryption System")
selected_mode = "ECB"
mode_buttons = []

# UI Elementos
tk.Label(root, text="Enter Text").pack()        # Texto
text_entry = tk.Text(root, height=5, width=50)
text_entry.pack()

tk.Label(root, text="\nEnter 16-Character Secret Key").pack()   # Key
key_entry = tk.Entry(root)
key_entry.pack()

tk.Label(root, text="\nSelect Mode").pack()     # Botones para el modo de encripcion
mode_frame = tk.Frame(root)
mode_frame.pack()
for mode in ["ECB", "CBC", "CFB"]:
    btn = tk.Button(mode_frame, text=mode, command=lambda m=mode: set_mode(m), bg="lightgray")
    btn.pack(side=tk.LEFT, padx=5)
    mode_buttons.append(btn)
update_mode_buttons()

tk.Label(root, text="\nSelect Action").pack()   # Botones para encriptar o desencriptar
action_frame = tk.Frame(root)
action_frame.pack(pady=5)
tk.Button(action_frame, text="Encrypt", command=lambda: perform_action("Encrypt")).pack(side=tk.LEFT, padx=5)
tk.Button(action_frame, text="Decrypt", command=lambda: perform_action("Decrypt")).pack(side=tk.LEFT, padx=5)

tk.Label(root, text="Result").pack()            # Resultado
result_entry = tk.Text(root, height=5, width=50)
result_entry.pack()

root.mainloop()