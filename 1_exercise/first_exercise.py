import tkinter as tk
from tkinter import messagebox

# Alfabeto extendido (ASCII 256 caracteres)
CHARSET = [chr(i) for i in range(256)]

def vigenere_encrypt(text, key):
    key_length = len(key)
    return ''.join(
        CHARSET[(ord(text[i]) + ord(key[i % key_length])) % 256] for i in range(len(text))
    )

def vigenere_decrypt(text, key):
    key_length = len(key)
    return ''.join(
        CHARSET[(ord(text[i]) - ord(key[i % key_length])) % 256] for i in range(len(text))
    )

def process_text(encrypt=True):
    text, key = text_entry.get(), key_entry.get()
    if not text or not key:
        messagebox.showerror("Error", "Text and key can't be empty")
        return
    result.set(vigenere_encrypt(text, key) if encrypt else vigenere_decrypt(text, key))

# Configuración de la ventana
root = tk.Tk()
root.title("Vigenère Cipher")
root.geometry("400x200")

# UI simplificada
tk.Label(root, text="Text:").pack()
text_entry = tk.Entry(root, width=50)
text_entry.pack()

tk.Label(root, text="Key:").pack()
key_entry = tk.Entry(root, width=50)
key_entry.pack()

result = tk.StringVar()
tk.Label(root, text="Result:").pack()
tk.Entry(root, textvariable=result, width=50, state='readonly').pack()

tk.Button(root, text="Encrypt", command=lambda: process_text(True)).pack()
tk.Button(root, text="Decrypt", command=lambda: process_text(False)).pack()

root.mainloop()
