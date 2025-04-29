import tkinter as tk
from tkinter import ttk, messagebox
import security, storage

# Configuración de estilo y constantes
BASE_FONT = ("Arial", 12)
BTN_FONT = ("Arial", 10)
TITLE_FONT = ("Arial", 16, "bold")
PAD = 5
# Variables de estado
root = tk.Tk()
root.title("Secure Password Manager")
current_user, entries, selected_index = None, [], None
search_var = tk.StringVar()
show_password = tk.BooleanVar(value=False)

# Ventana inicial de bienvenida
def start_view():
    setup_clear_window()
    root.geometry("800x400")
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text="Welcome", font=TITLE_FONT).pack(pady=10)
    ttk.Button(frame, text="Login", width=20, command=lambda: auth_modal(True)).pack(pady=PAD)
    ttk.Button(frame, text="Register", width=20, command=lambda: auth_modal(False)).pack(pady=PAD)

# Modal genérico de autenticación (login o registro)
def auth_modal(login=True):
    import user_manager
    title, auth_func = ("Login", user_manager.authenticate_user) if login else ("Register", user_manager.register_user)
    win = tk.Toplevel(root)
    win.title(title)
    center_window(win, width=350, height=125)
    win.transient(root)
    win.grab_set()

    container = ttk.Frame(win, padding=10)
    container.pack(fill='both', expand=True)
    user_var, pass_var = tk.StringVar(), tk.StringVar()
    labeled_entry(container, "Username:", user_var, row=0)
    labeled_entry(container, "Password:", pass_var, row=1, show='*')

    def submit():
        u, p = user_var.get().strip(), pass_var.get().strip()
        if not u or not p:
            messagebox.showerror("Error", "Both fields are required.")
            return
        try:
            if auth_func(u, p):
                win.destroy()
                initialize_user_session(u)
            else:
                messagebox.showerror("Error", "Invalid credentials.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(container, text="Submit", command=submit).grid(row=2, column=0, columnspan=2, pady=(PAD, 0))
    win.wait_window()

# Inicialización de sesión y carga de datos
def initialize_user_session(username):
    global current_user, entries
    try:
        current_user = username
        entries = storage.load_entries(username)
        main_view()
    except Exception as e:
        messagebox.showerror("Error", f"Session init failed: {e}")
        start_view()

# Cerrar sesión
def logout():
    if current_user and messagebox.askyesno("Logout", "Are you sure?"):
        try:
            storage.save_entries(current_user, entries)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {str(e)}")
    root.destroy()

# Vista principal con Treeview y acciones
def main_view():
    setup_clear_window()
    ttk.Label(root, text="Password Manager", font=TITLE_FONT).pack(pady=10)
    
    # Búsqueda
    sf = ttk.Frame(root, padding=PAD)
    sf.pack(fill='x')
    ttk.Label(sf, text="Search Title:", font=BASE_FONT).grid(row=0, column=0, padx=(0, PAD), pady=PAD, sticky='w')
    ttk.Entry(sf, textvariable=search_var).grid(row=0, column=1, padx=(0, PAD), pady=PAD, sticky='ew')
    ttk.Button(sf, text="Search", command=search_entry).grid(row=0, column=2, padx=(0, PAD), pady=PAD, sticky='e')
    sf.columnconfigure(1, weight=1)

    # Treeview
    global tree
    cols = ('Title', 'Password', 'URL', 'Notes')
    tree = ttk.Treeview(root, columns=cols, show='headings', height=10)
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, anchor='center')
    tree.pack(fill='both', expand=True, padx=10, pady=10)
    tree.bind('<<TreeviewSelect>>', on_select)

    # Botones
    bf = ttk.Frame(root, padding=5)
    bf.pack(fill='x')
    actions = [
        ("Add Entry", lambda: entry_modal(False)),
        ("Delete Entry", delete_entry),
        ("Update Entry", lambda: entry_modal(True)),
        ("Show Password", toggle_password),
        ("Copy Password", copy_password),
        ("Logout", logout)
    ]
    for i, (text, cmd) in enumerate(actions):
        btn = ttk.Button(bf, text=text, command=cmd)
        btn.grid(row=0, column=i, sticky='ew', padx=PAD, pady=PAD)
        bf.columnconfigure(i, weight=1)
    refresh_list()

# Agregar/actualizar entrada
def entry_modal(update=False):
    global selected_index
    if update and selected_index is None:
        return

    data = entries[selected_index] if update else {}
    win = tk.Toplevel(root)
    win.title("Update Entry" if update else "Add Entry")
    center_window(win, width=400, height=250)
    win.transient(root)
    win.grab_set()

    container = ttk.Frame(win, padding=10)
    container.pack(fill='both', expand=True)

    # Descifrar la contraseña previa si es una actualización
    previous_password = ""
    if update:
        try:
            previous_password = security.decrypt_data(data['EncryptedPassword'].encode()).decode()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
            win.destroy()
            return

    vars_map = {
        'Title': tk.StringVar(value=data.get('Title', '')),
        'URL': tk.StringVar(value=data.get('URL', '')),
        'Notes': tk.StringVar(value=data.get('Notes', '')),
        'Password': tk.StringVar(value=previous_password)
    }

    def toggle_password_visibility():
        if show_password.get():
            password_entry.config(show='*')
            show_password.set(False)
        else:
            password_entry.config(show='')
            show_password.set(True)

    # Campos de entrada
    labeled_entry(container, "Title:", vars_map['Title'], row=0)
    password_entry = labeled_entry(container, "Password:", vars_map['Password'], row=1, show='*')
    global show_password
    ttk.Button(container, text="Random password", command=lambda v=vars_map['Password']: v.set(random_password())).grid(row=2, column=1, pady=(PAD, 0))
    ttk.Button(container, text="Show password", command=toggle_password_visibility).grid(row=3, column=1, pady=(PAD, 0))
    labeled_entry(container, "URL:", vars_map['URL'], row=4)
    labeled_entry(container, "Notes:", vars_map['Notes'], row=5)

    # Botón de envío
    def submit():
        t, pw = vars_map['Title'].get().strip(), vars_map['Password'].get().strip()
        if not t or not pw:
            messagebox.showerror("Error", "Title and Password are required.")
            return
        
        try:
            new_data = {
                'Title': t,
                'EncryptedPassword': security.encrypt_data(pw.encode()).decode(),
                'URL': vars_map['URL'].get(),
                'Notes': vars_map['Notes'].get()
            }
            if update:
                entries[selected_index].update(new_data)
            else:
                entries.append(new_data)
            refresh_list()
            win.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")

    ttk.Button(container, text="Submit", command=submit).grid(row=6, column=0, columnspan=2, pady=(PAD, 0))

# Eliminar entrada
def delete_entry():
    global selected_index
    if selected_index is not None and messagebox.askyesno("Confirm", "Delete this entry?"):
        del entries[selected_index]
        selected_index = None
        refresh_list()

# Mostrar/ocultar contraseña
def toggle_password():
    if selected_index is None: return
    e = entries[selected_index]
    display = '************' if show_password.get() else security.decrypt_data(e['EncryptedPassword'].encode()).decode()
    show_password.set(not show_password.get())
    tree.item(tree.selection()[0], values=(e['Title'], display, e['URL'], e['Notes']))

# Copiar contraseña al portapapeles
def copy_password():
    if selected_index is None: return
    try:
        pw = security.decrypt_data(entries[selected_index]['EncryptedPassword'].encode()).decode()
        root.clipboard_clear()
        root.clipboard_append(pw)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Otras funciones
def search_entry():
    title = search_var.get().strip().lower()
    for idx, e in enumerate(entries):
        if e['Title'].lower() == title:
            tree.selection_set(tree.get_children()[idx])
            on_select()
            return
    messagebox.showinfo("Not found", "No entry with that title.")

# Genera contraseña aleatoria
def random_password():
    import random, string, secrets
    mandatory = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]
    # Resto de caracteres aleatorios
    alphabet = string.ascii_letters + string.digits + string.punctuation
    rest = [secrets.choice(alphabet) for _ in range(12)]
    # Mezclar y devolver
    password_chars = mandatory + rest
    random.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)

# Refresca la lista de entradas
def refresh_list():
    tree.delete(*tree.get_children())
    for e in entries:
        tree.insert('', 'end', values=(e['Title'], '************', e['URL'], e['Notes']))

# Selección de entrada en el Treeview
def on_select(event=None):
    global selected_index
    sel = tree.selection()
    selected_index = tree.index(sel[0]) if sel else None

# Limpia la ventana actual y prepara el estilo
def setup_clear_window():
    for widget in root.winfo_children(): widget.destroy()
    style = ttk.Style()
    style.configure("TLabel", font=BASE_FONT)
    style.configure("TButton", font=BTN_FONT)
    style.configure("Treeview.Heading", font=(BASE_FONT[0], BASE_FONT[1], "bold"))

# Función común para centrar ventanas
def center_window(window, width=400, height=300):
    x = (window.winfo_screenwidth() - width) // 2
    y = (window.winfo_screenheight() - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")

# Helper para crear fila de formulario con grid
def labeled_entry(parent, label_text, text_var, row, show=None):
    ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky='w', padx=PAD, pady=PAD)
    entry = ttk.Entry(parent, textvariable=text_var, show=show)
    entry.grid(row=row, column=1, sticky='ew', padx=PAD, pady=PAD)
    parent.columnconfigure(1, weight=1)
    return entry

if __name__ == '__main__':
    root.protocol("WM_DELETE_WINDOW", logout)
    start_view()
    root.mainloop()
