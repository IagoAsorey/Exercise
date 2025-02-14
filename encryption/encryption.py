import tkinter as tk
from tkinter import ttk, messagebox

# Alfabeto extendido (ASCII 256 caracteres)
CHARSET = [chr(i) for i in range(256)]

# Función para cifrar con Vigenère
def vigenere_encrypt(text, key):
    key_length = len(key)
    return ''.join(
        CHARSET[(ord(text[i]) + ord(key[i % key_length])) % 256] if text[i] in CHARSET else text[i]
        for i in range(len(text))
    )

# Función para descifrar con Vigenère
def vigenere_decrypt(text, key):
    key_length = len(key)
    return ''.join(
        CHARSET[(ord(text[i]) - ord(key[i % key_length])) % 256] if text[i] in CHARSET else text[i]
        for i in range(len(text))
    )

# Función para manejar el cifrado
def encrypt_text():
    text, key = text_entry.get(), key_entry.get()
    if not text or not key:
        messagebox.showerror("Error", "El texto y la clave no pueden estar vacíos")
        return
    result_entry.delete(0, tk.END)
    result_entry.insert(0, vigenere_encrypt(text, key))

# Función para manejar el descifrado
def decrypt_text():
    text, key = text_entry.get(), key_entry.get()
    if not text or not key:
        messagebox.showerror("Error", "El texto y la clave no pueden estar vacíos")
        return
    result_entry.delete(0, tk.END)
    result_entry.insert(0, vigenere_decrypt(text, key))

# Configuración de la ventana principal
root = tk.Tk()
root.title("Cifrado Vigenère - Mejorado")
root.geometry("450x250")
root.configure(bg="#2E2E2E")  # Modo oscuro

# Estilos ttk
style = ttk.Style()
style.configure("TLabel", foreground="white", background="#2E2E2E")
style.configure("TButton", padding=6, relief="flat", background="#444")
style.configure("TEntry", fieldbackground="#444", foreground="white")

# UI Mejorada
ttk.Label(root, text="Texto:").grid(row=0, column=0, padx=10, pady=5)
text_entry = ttk.Entry(root, width=50)
text_entry.grid(row=0, column=1, padx=10, pady=5)

ttk.Label(root, text="Clave:").grid(row=1, column=0, padx=10, pady=5)
key_entry = ttk.Entry(root, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=5)

button_frame = ttk.Frame(root)
button_frame.grid(row=2, column=0, columnspan=2, pady=10)

ttk.Button(button_frame, text="Cifrar", command=encrypt_text).grid(row=0, column=0, padx=5)
ttk.Button(button_frame, text="Descifrar", command=decrypt_text).grid(row=0, column=1, padx=5)

result_entry = ttk.Entry(root, width=50)
result_entry.grid(row=3, column=1, padx=10, pady=5)

ttk.Label(root, text="Resultado:").grid(row=3, column=0, padx=10, pady=5)

root.mainloop()
