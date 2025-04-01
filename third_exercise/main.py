import tkinter as tk
from tkinter import ttk
import rsa
import math

class RSASystemApp:
    # Crea la pestaña en la que se muestran los sistemas, también las 2 ventanas
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption/Decryption Systems")
        
        self.style = ttk.Style()
        self.style.configure('TNotebook.Tab', background='#d9d9d9')
        self.style.map('TNotebook.Tab',
                      background=[('selected', '#4a4a4a')],
                      foreground=[('selected', 'blue')])
        
        self.notebook = ttk.Notebook(root)
        self.system1_frame = ttk.Frame(self.notebook)
        self.system2_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.system1_frame, text="System 1 (With Library)")
        self.notebook.add(self.system2_frame, text="System 2 (Without Library)")
        self.notebook.pack(expand=1, fill="both")
        
        self.setup_system1()
        self.setup_system2()
        self.pubkey, self.privkey = rsa.newkeys(512)

    # Pestaña del sistema 1
    def setup_system1(self):
        frame = self.system1_frame
        ttk.Label(frame, text="Text:").grid(row=0, column=0, padx=5, pady=5)
        self.text_entry_s1 = tk.Text(frame, height=5, width=50)
        self.text_entry_s1.grid(row=0, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_system1).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_system1).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(frame, text="Result:").grid(row=2, column=0, padx=5, pady=5)
        self.result_s1 = tk.Text(frame, height=5, width=50)
        self.result_s1.grid(row=2, column=1, padx=5, pady=5)

    # Encripta usando libreria RSA
    def encrypt_system1(self):
        text = self.text_entry_s1.get("1.0", "end-1c")
        try:
            ciphertext = rsa.encrypt(text.encode(), self.pubkey)
            self.result_s1.delete("1.0", tk.END)
            self.result_s1.insert("1.0", ciphertext.hex())
        except Exception as e:
            self.result_s1.delete("1.0", tk.END)
            self.result_s1.insert("1.0", f"Error: {str(e)}")

    # Desencripta usando librería RSA
    def decrypt_system1(self):
        text = self.text_entry_s1.get("1.0", "end-1c").strip()
        try:
            ciphertext = bytes.fromhex(text)
            plaintext = rsa.decrypt(ciphertext, self.privkey).decode()
            self.result_s1.delete("1.0", tk.END)
            self.result_s1.insert("1.0", plaintext)
        except Exception as e:
            self.result_s1.delete("1.0", tk.END)
            self.result_s1.insert("1.0", f"Error: {str(e)}")

    # Pestaña del sistema 2
    def setup_system2(self):
        frame = self.system2_frame
        
        ttk.Label(frame, text="Prime p:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.p_entry = ttk.Entry(frame)
        self.p_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(frame, text="Prime q:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.q_entry = ttk.Entry(frame)
        self.q_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(frame, text="Plaintext (number):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.x_entry = ttk.Entry(frame)
        self.x_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_system2).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_system2).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(frame, text="Result:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.result_2 = ttk.Label(frame, text="", relief="sunken", anchor="w")
        self.result_2.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        
        frame.columnconfigure(1, weight=1)
        self.n = self.phi = self.e = self.d = self.y = None

    # Calcula parámetrs necesarior para el cifrado
    def compute_parameters(self):
        try:
            p, q = int(self.p_entry.get()), int(self.q_entry.get())
            if p > 1000 or q > 1000:
                return False
        except:
            return False

        # Verifia que p y q son primos
        def is_prime(n):
            return n > 1 and all(n % i for i in range(2, int(math.isqrt(n)) + 1))

        if not (is_prime(p) and is_prime(q)):
            return False
            
        self.n, self.phi = p * q, (p - 1) * (q - 1)
        if self.n < 256:
            return False

        # Encuentra e coprimo con phi
        self.e = next(e for e in range(3, self.phi, 2) if math.gcd(e, self.phi) == 1)
        self.d = pow(self.e, -1, self.phi)  # Calcula el inverso modular directamente
        return True

    # Algoritmo de Euclides para el encontrar el inverso modular
    def extended_gcd(self, a, b):
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0

    # Encripta sin usar libreria
    def encrypt_system2(self):
        if not self.compute_parameters():
            self.result_2.config(text="Invalid parameters")
            return
        
        plaintext = self.x_entry.get()
        try:
            ascii_values = [ord(c) for c in plaintext]      # Convertir texto a valores numéricos
            if any(val >= self.n for val in ascii_values):  # Verificar que todos los valores sean menores que n
                raise ValueError("Error")
                
            # Encriptar cada carácter
            ciphertext = [str(pow(val, self.e, self.n)) for val in ascii_values]
            self.y = ",".join(ciphertext)
            self.result_2.config(text=self.y)
            
            with open("rsa_data.txt", "w") as f:        # Guardar automáticamente
                f.write(f"{self.y}\n{self.n}\n{self.e}")
                
        except Exception as e:
            self.result_2.config(text=f"Error: {str(e)}")

    # Desencripta sin usar librería
    def decrypt_system2(self):
        try:
            with open("rsa_data.txt", "r") as f:        # Lee los datos cifrados del archivo
                y, n, e = f.read().splitlines()
                n, e = int(n), int(e)
                
            ciphertext = list(map(int, y.split(',')))   # Convertir a lista de números cifrados
            
            # Factorizar n, para encontrar p y q
            for i in range(2, int(math.isqrt(n)) + 1):
                if n % i == 0:
                    p, q = i, n // i
                    break
            
            if p is None:
                raise ValueError("Can't factorize n")
            
            # Calcula phi(n)
            phi, d = (p - 1) * (q - 1), pow(e, -1, (p - 1) * (q - 1))
            
            plaintext = ''.join(chr(pow(val, d, n)) for val in ciphertext)
            self.result_2.config(text=plaintext)
                        
        except Exception as e:
            self.result_2.config(text=f"Error: {str(e)}")

def main():
    root = tk.Tk()
    app = RSASystemApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()