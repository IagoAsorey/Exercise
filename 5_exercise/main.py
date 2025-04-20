import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import random, string
import user_manag, security, storage

# Variables globales
root = tk.Tk()
root.title("Secure Password Manager")
# Estados de la aplicación
current_user = None
fernet = None
entries = []
selected_index = None
# Variables de control
search_var = tk.StringVar()
url_var = tk.StringVar()
notes_var = tk.StringVar()
password_var = tk.StringVar(value='************')
show_password = tk.BooleanVar(value=False)

# Interfaz inicial de login/registro
def start():
    clear_window()

    # Estilo general
    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 10))

    # Título principal
    title_frame = ttk.Frame(root, padding=20)
    title_frame.pack(fill='x', pady=10)
    ttk.Label(title_frame, text="Welcome", font=("Arial", 16, "bold")).pack()

    # Opciones de Login y Registro
    button_frame = ttk.Frame(root, padding=20)
    button_frame.pack(fill='both', expand=True, pady=20)
    ttk.Button(button_frame, text="Login", width=20, command=login).pack(pady=10)
    ttk.Button(button_frame, text="Register", width=20, command=register).pack(pady=10)

# Interfaz principal
def main():
    clear_window()

    # Estilo general
    style = ttk.Style()
    style.configure("TLabel", font=("Arial", 12))
    style.configure("TButton", font=("Arial", 10))
    style.configure("Treeview.Heading", font=("Arial", 11, "bold"))

    # Título principal
    title_frame = ttk.Frame(root, padding=10)
    title_frame.pack(fill='x')
    ttk.Label(title_frame, text="Password Manager", font=("Arial", 16, "bold")).pack()

    # Barra de búsqueda
    search_frame = ttk.Frame(root, padding=10)
    search_frame.pack(fill='x', padx=10, pady=5)
    ttk.Label(search_frame, text="Search Title:").pack(side='left', padx=5)
    ttk.Entry(search_frame, textvariable=search_var, width=100).pack(side='left', padx=5)
    ttk.Button(search_frame, text="Search", command=search_entry).pack(side='left', padx=5)

    # Lista de entradas
    global tree
    tree_frame = ttk.Frame(root, padding=10)
    tree_frame.pack(fill='both', expand=True, padx=10, pady=5)
    tree = ttk.Treeview(tree_frame, columns=('Title', 'Password', 'URL', 'Notes'), show='headings', height=15)
    for col in ('Title', 'Password', 'URL', 'Notes'):
        tree.heading(col, text=col)
        tree.column(col, width=150, anchor='center')
    tree.pack(fill='both', expand=True, padx=5, pady=5)
    tree.bind('<<TreeviewSelect>>', on_select)

    # Botones de acción
    button_frame = ttk.Frame(root, padding=10)
    button_frame.pack(fill='x', padx=10, pady=5)
    buttons = [
        ('Add Entry', add_entry),
        ('Delete Entry', delete_entry),
        ('Update Password', update_entry),
        ('Show Password', toggle_password),
        ('Copy Password', copy_password),
        ('Logout', logout)
    ]
    for text, cmd in buttons:
        ttk.Button(button_frame, text=text, command=cmd).pack(side='left', padx=5)

    # Refrescar la lista de entradas
    refresh_list()

# Registra un nuevo usuario
def register():
    username = simpledialog.askstring("Register", "Enter a new username:")
    if not username:
        messagebox.showerror("Error", "Username is required.")
        return
    
    pwd = simpledialog.askstring("Register", "Enter a password:", show='*')
    if not pwd:
        messagebox.showerror("Error", "Password is required.")
        return
    
    try:
        user_manag.register_user(username, pwd)
        initialize_user_session(username, pwd)
        messagebox.showinfo("Success", "Registration successful.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Inicia sesión de usuario
def login():
    username = simpledialog.askstring("Login", "Enter your username:")
    if not username:
        messagebox.showerror("Error", "Username is required.")
        return
    
    pwd = simpledialog.askstring("Login", "Enter your password:", show='*')
    if not pwd:
        messagebox.showerror("Error", "Password is required.")
        return
    
    if user_manag.authenticate_user(username, pwd):
        initialize_user_session(username, pwd)
    else:
        messagebox.showerror("Error", "Invalid username or password.")

# Inicializa la sesión del usuario
def initialize_user_session(username, password):
    global current_user, fernet, entries
    try:
        current_user = username
        fernet = security.initialize_encryption(username, password)
        entries = storage.load_entries(fernet, username)
        main()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to initialize session: {str(e)}")
        logout()

# Cierra sesión de usuario y la aplicación
def logout():
    try:
        if not messagebox.askyesno("Log out", "Are you sure you want to log out?"):
            return
        
        if current_user and fernet:
            storage.save_entries(fernet, current_user, entries)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save data: {e}")
    finally:
        root.destroy()

# Busca una entrada por título
def search_entry():
    title = search_var.get().strip().lower()
    for idx, entry in enumerate(entries):
        if entry['Title'].lower() == title:
            tree.selection_set(tree.get_children()[idx])
            on_select()
            return
    messagebox.showinfo("Not found", "No entry with that title.")

# Agrega una nueva entrada
def add_entry():
    title = simpledialog.askstring("Title", "Enter a title:")
    if not title:
        return messagebox.showerror("Error", "Title is required.")
    
    password = select_password()
    if not password:
        return messagebox.showerror("Error", "Password is required.")
    
    new_entry = {
        'Title': title,
        'EncryptedPassword': security.encrypt_data(fernet, password.encode()).decode(),
        'URL': simpledialog.askstring("URL/App", "Enter a URL or app name:") or '',
        'Notes': simpledialog.askstring("Notes", "Enter notes:") or ''
    }
    entries.append(new_entry)
    refresh_list()

# Elimina una entrada seleccionada
def delete_entry():
    global selected_index
    if selected_index is None:
        return
    
    if not messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?"):
        return
    
    del entries[selected_index]
    selected_index = None  # Reinicia el índice seleccionado
    refresh_list()

# Actualiza una entrada existente
def update_entry():
    if selected_index is None:
        return
    
    entry = entries[selected_index]
    entry.update({
        'URL': url_var.get() or entry['URL'],
        'Notes': notes_var.get() or entry['Notes']
    })

    if messagebox.askyesno("Update", "Do you want to change the password?") and (new_password := select_password()):
        entry['EncryptedPassword'] = security.encrypt_data(fernet, new_password.encode()).decode()
    
    refresh_list()

# Muestra u oculta la contraseña de la entrada seleccionada
def toggle_password():
    if selected_index is None:
        return

    entry = entries[selected_index]
    if show_password.get():
        password_var.set('************')
    else:
        decrypted = security.decrypt_data(fernet, entry['EncryptedPassword'].encode())
        password_var.set(decrypted.decode())

    show_password.set(not show_password.get())
    tree.item(tree.selection()[0], values=(
        entry['Title'], 
        password_var.get(), 
        entry['URL'], 
        entry['Notes']
    ))

# Copia la contraseña de la entrada seleccionada al port
def copy_password():
    if selected_index is None:
        return
    
    try:
        decrypted = security.decrypt_data(fernet, entries[selected_index]['EncryptedPassword'].encode())
        root.clipboard_clear()
        root.clipboard_append(decrypted.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Failed to copy password: {str(e)}")

# Genera una contraseña aleatoria o permite ingresarla manualmente
def select_password() -> str:
    choose_passw = tk.Toplevel(root)
    choose_passw.title("Password")
    choose_passw.geometry("300x150")
    password = [None]

    # Genera una contraseña aleatoria
    def on_generate():
        chars = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ] + random.choices(string.ascii_letters + string.digits + string.punctuation, k=4)
        random.shuffle(chars)
        password[0] = ''.join(chars)
        choose_passw.destroy()

    ttk.Label(choose_passw, text="Choose password method:").pack(pady=10)
    ttk.Button(choose_passw, text="Generate Random", command=on_generate).pack(fill='x', padx=20, pady=5)
    ttk.Button(choose_passw, text="Enter manually", command=lambda: [choose_passw.destroy(), password.__setitem__(0, simpledialog.askstring("Password", "Enter password:", show='*'))]).pack(fill='x', padx=20)

    # Centrar la ventana y esperar a que se cierre
    choose_passw.transient(root)
    choose_passw.grab_set()
    choose_passw.wait_window()

    return password[0] or ""

# Actualiza la lista de entradas en el Treeview
def refresh_list():
    tree.delete(*tree.get_children())
    for entry in entries:
        tree.insert('', 'end', values=(entry['Title'], '************', entry['URL'], entry['Notes']))

# Limpia la ventana
def clear_window():
    for w in root.winfo_children():
        w.destroy()

# Maneja la selección de una entrada en el Treeview
def on_select(event=None):
    global selected_index
    sel = tree.selection()
    selected_index = tree.index(sel[0]) if sel else None

    if selected_index is not None:
        entry = entries[selected_index]
        url_var.set(entry['URL'])
        notes_var.set(entry['Notes'])

if __name__ == '__main__':
    start()
    root.mainloop()
