import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import secrets
import string

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

VAULT_FILE = "vault.sec"
SALT_FILE = "salt.bin"
ITERATIONS = 300_000

# ---------------- CRYPTO ---------------- #

def get_or_create_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

def derive_fernet(master_password: str) -> Fernet:
    salt = get_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    key = base64.urlsafe_b64encode(
        kdf.derive(master_password.encode())
    )
    return Fernet(key)

# ---------------- GUI APP ---------------- #

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("500x560")
        self.root.resizable(False, False)

        self.fernet = self.authenticate()
        if not self.fernet:
            root.destroy()
            return

        self.vault = {}
        self.load_vault()

        self.create_widgets()
        self.refresh_list()

    # ---------------- AUTH ---------------- #

    def authenticate(self):
        pw = simpledialog.askstring(
            "Master Password",
            "Enter Master Password:",
            show="*"
        )
        if not pw:
            return None

        fernet = derive_fernet(pw)

        if os.path.exists(VAULT_FILE):
            try:
                with open(VAULT_FILE, "rb") as f:
                    fernet.decrypt(f.read())
            except InvalidToken:
                messagebox.showerror(
                    "Error",
                    "Wrong master password or corrupted vault"
                )
                return None
        else:
            with open(VAULT_FILE, "wb") as f:
                f.write(fernet.encrypt(json.dumps({}).encode()))

        return fernet

    # ---------------- UI ---------------- #

    def create_widgets(self):
        tk.Label(
            self.root,
            text="🔐 Secure Password Manager",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=10)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Website").grid(row=0, column=0, sticky="w")
        tk.Label(frame, text="Username").grid(row=1, column=0, sticky="w")
        tk.Label(frame, text="Password").grid(row=2, column=0, sticky="w")

        self.website = tk.Entry(frame, width=30)
        self.username = tk.Entry(frame, width=30)
        self.password = tk.Entry(frame, width=30, show="*")

        self.website.grid(row=0, column=1, pady=5)
        self.username.grid(row=1, column=1, pady=5)
        self.password.grid(row=2, column=1, pady=5)

        tk.Button(
            frame, text="Show",
            command=self.toggle_password,
            width=6
        ).grid(row=2, column=2, padx=5)

        tk.Button(
            self.root,
            text="Save Password",
            width=30,
            command=self.save_entry
        ).pack(pady=5)

        tk.Button(
            self.root,
            text="Generate Password",
            width=30,
            command=self.generate_password
        ).pack(pady=5)

        self.tree = ttk.Treeview(
            self.root,
            columns=("Website", "Username"),
            show="headings",
            height=8
        )
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        self.tree.pack(pady=10)

        action = tk.Frame(self.root)
        action.pack(pady=10)

        tk.Button(action, text="Load", width=12, command=self.load_entry).grid(row=0, column=0, padx=5)
        tk.Button(action, text="Delete", width=12, command=self.delete_entry).grid(row=0, column=1, padx=5)

    # ---------------- VAULT ---------------- #

    def load_vault(self):
        with open(VAULT_FILE, "rb") as f:
            decrypted = self.fernet.decrypt(f.read())
            self.vault = json.loads(decrypted.decode())

    def save_vault(self):
        data = json.dumps(self.vault).encode()
        encrypted = self.fernet.encrypt(data)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)

    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for site, entry in self.vault.items():
            self.tree.insert("", "end", values=(site, entry["username"]))

    # ---------------- LOGIC ---------------- #

    def toggle_password(self):
        self.password.config(show="" if self.password.cget("show") else "*")

    def generate_password(self):
        length = simpledialog.askinteger(
            "Password Length",
            "Enter password length (8–64):",
            minvalue=8,
            maxvalue=64
        )
        if not length:
            return

        charset = (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            string.punctuation
        )

        password = "".join(secrets.choice(charset) for _ in range(length))

        self.password.delete(0, tk.END)
        self.password.insert(0, password)

        messagebox.showinfo("Generated", "Strong password generated")

    def save_entry(self):
        site = self.website.get()
        user = self.username.get()
        pw = self.password.get()

        if not site or not user or not pw:
            messagebox.showwarning("Error", "All fields required")
            return

        self.vault[site] = {"username": user, "password": pw}
        self.save_vault()
        self.refresh_list()

        self.website.delete(0, tk.END)
        self.username.delete(0, tk.END)
        self.password.delete(0, tk.END)

        messagebox.showinfo("Saved", "Password securely stored")

    def load_entry(self):
        sel = self.tree.focus()
        if not sel:
            return

        site, user = self.tree.item(sel)["values"]
        pw = self.vault[site]["password"]

        self.website.delete(0, tk.END)
        self.username.delete(0, tk.END)
        self.password.delete(0, tk.END)

        self.website.insert(0, site)
        self.username.insert(0, user)
        self.password.insert(0, pw)

    def delete_entry(self):
        sel = self.tree.focus()
        if not sel:
            return

        site = self.tree.item(sel)["values"][0]
        if messagebox.askyesno("Confirm", f"Delete {site}?"):
            del self.vault[site]
            self.save_vault()
            self.refresh_list()

# ---------------- RUN ---------------- #

if __name__ == "__main__":
    root = tk.Tk()
    PasswordManager(root)
    root.mainloop()
