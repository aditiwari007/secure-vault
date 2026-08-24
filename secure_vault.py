import os
import json
import uuid
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "Personal Secure Vault"

BASE_DIR = Path(__file__).resolve().parent
VAULT_DIR = BASE_DIR / "vault"
DATA_DIR = BASE_DIR / "vault_data"

SALT_FILE = DATA_DIR / "salt.bin"
MANIFEST_FILE = DATA_DIR / "manifest.enc"

ITERATIONS = 600_000

VAULT_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)


# ============================================================
# PASSWORD -> ENCRYPTION KEY
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Password ko encryption key mein convert karta hai.
    Password directly encryption key ke roop mein use nahi hota.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )

    key = kdf.derive(password.encode("utf-8"))

    return base64.urlsafe_b64encode(key)


# ============================================================
# MANIFEST FUNCTIONS
# ============================================================

def save_manifest(fernet: Fernet, manifest: dict):
    """
    Vault ki file information ko encrypted form mein save karta hai.
    """

    data = json.dumps(
        manifest,
        ensure_ascii=False,
        indent=2
    ).encode("utf-8")

    encrypted = fernet.encrypt(data)

    with open(MANIFEST_FILE, "wb") as f:
        f.write(encrypted)


def load_manifest(fernet: Fernet) -> dict:
    """
    Encrypted manifest ko decrypt karta hai.
    """

    if not MANIFEST_FILE.exists():
        return {
            "files": []
        }

    try:
        with open(MANIFEST_FILE, "rb") as f:
            encrypted = f.read()

        decrypted = fernet.decrypt(encrypted)

        return json.loads(decrypted.decode("utf-8"))

    except InvalidToken:
        raise ValueError("Wrong password")

    except Exception as e:
        raise ValueError(f"Manifest error: {e}")


# ============================================================
# MAIN APPLICATION
# ============================================================

class SecureVaultApp:

    def __init__(self, root):
        self.root = root

        self.root.title(APP_NAME)
        self.root.geometry("850x550")
        self.root.minsize(750, 450)

        self.fernet = None
        self.manifest = None

        self.setup_style()

        self.show_login_screen()

    # --------------------------------------------------------
    # UI STYLE
    # --------------------------------------------------------

    def setup_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except:
            pass

        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold")
        )

        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 11)
        )

        style.configure(
            "Big.TButton",
            font=("Segoe UI", 11),
            padding=10
        )

    # --------------------------------------------------------
    # CLEAR SCREEN
    # --------------------------------------------------------

    def clear_screen(self):

        for widget in self.root.winfo_children():
            widget.destroy()

    # ========================================================
    # FIRST TIME SETUP
    # ========================================================

    def show_setup_screen(self):

        self.clear_screen()

        frame = ttk.Frame(self.root, padding=40)
        frame.pack(expand=True)

        ttk.Label(
            frame,
            text="🔐 Create Your Vault",
            style="Title.TLabel"
        ).pack(pady=(0, 10))

        ttk.Label(
            frame,
            text="Create a strong password for your personal vault.",
            style="Subtitle.TLabel"
        ).pack(pady=(0, 30))

        ttk.Label(
            frame,
            text="Password:"
        ).pack(anchor="w")

        password_entry = ttk.Entry(
            frame,
            show="*",
            width=40
        )

        password_entry.pack(pady=(5, 15))

        ttk.Label(
            frame,
            text="Confirm Password:"
        ).pack(anchor="w")

        confirm_entry = ttk.Entry(
            frame,
            show="*",
            width=40
        )

        confirm_entry.pack(pady=(5, 20))

        def create_vault():

            password = password_entry.get()
            confirm = confirm_entry.get()

            if len(password) < 8:
                messagebox.showwarning(
                    "Weak Password",
                    "Password kam se kam 8 characters ka hona chahiye."
                )
                return

            if password != confirm:
                messagebox.showerror(
                    "Error",
                    "Passwords match nahi kar rahe."
                )
                return

            try:

                salt = os.urandom(16)

                with open(SALT_FILE, "wb") as f:
                    f.write(salt)

                key = derive_key(password, salt)

                self.fernet = Fernet(key)

                self.manifest = {
                    "files": []
                }

                save_manifest(
                    self.fernet,
                    self.manifest
                )

                messagebox.showinfo(
                    "Success",
                    "Vault successfully create ho gaya!"
                )

                self.show_vault()

            except Exception as e:

                messagebox.showerror(
                    "Error",
                    f"Vault create nahi ho saka:\n{e}"
                )

        ttk.Button(
            frame,
            text="Create Secure Vault",
            command=create_vault,
            style="Big.TButton"
        ).pack(fill="x")

    # ========================================================
    # LOGIN SCREEN
    # ========================================================

    def show_login_screen(self):

        self.clear_screen()

        if not SALT_FILE.exists() or not MANIFEST_FILE.exists():

            self.show_setup_screen()
            return

        frame = ttk.Frame(self.root, padding=40)
        frame.pack(expand=True)

        ttk.Label(
            frame,
            text="🔐 Personal Secure Vault",
            style="Title.TLabel"
        ).pack(pady=(0, 10))

        ttk.Label(
            frame,
            text="Enter your password to unlock the vault.",
            style="Subtitle.TLabel"
        ).pack(pady=(0, 30))

        ttk.Label(
            frame,
            text="Password:"
        ).pack(anchor="w")

        password_entry = ttk.Entry(
            frame,
            show="*",
            width=40
        )

        password_entry.pack(pady=(5, 20))

        def unlock():

            password = password_entry.get()

            if not password:
                messagebox.showwarning(
                    "Password Required",
                    "Password enter karo."
                )
                return

            try:

                with open(SALT_FILE, "rb") as f:
                    salt = f.read()

                key = derive_key(password, salt)

                test_fernet = Fernet(key)

                manifest = load_manifest(
                    test_fernet
                )

                self.fernet = test_fernet
                self.manifest = manifest

                self.show_vault()

            except ValueError:

                messagebox.showerror(
                    "Access Denied",
                    "Wrong password!"
                )

            except Exception as e:

                messagebox.showerror(
                    "Error",
                    f"Vault open nahi ho saka:\n{e}"
                )

        ttk.Button(
            frame,
            text="🔓 Unlock Vault",
            command=unlock,
            style="Big.TButton"
        ).pack(fill="x")

        password_entry.bind(
            "<Return>",
            lambda event: unlock()
        )

        password_entry.focus()

    # ========================================================
    # VAULT SCREEN
    # ========================================================

    def show_vault(self):

        self.clear_screen()

        # Header
        header = ttk.Frame(
            self.root,
            padding=(20, 15)
        )

        header.pack(fill="x")

        ttk.Label(
            header,
            text="🔐 My Secure Vault",
            style="Title.TLabel"
        ).pack(side="left")

        ttk.Button(
            header,
            text="🔒 Lock",
            command=self.lock_vault
        ).pack(side="right")

        # Buttons
        button_frame = ttk.Frame(
            self.root,
            padding=(20, 5)
        )

        button_frame.pack(fill="x")

        ttk.Button(
            button_frame,
            text="➕ Add Files",
            command=self.add_files
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            button_frame,
            text="📤 Export",
            command=self.export_file
        ).pack(side="left", padx=8)

        ttk.Button(
            button_frame,
            text="🗑 Delete",
            command=self.delete_file
        ).pack(side="left", padx=8)

        ttk.Button(
            button_frame,
            text="🔄 Refresh",
            command=self.refresh_list
        ).pack(side="left", padx=8)

        # File list
        list_frame = ttk.Frame(
            self.root,
            padding=20
        )

        list_frame.pack(
            fill="both",
            expand=True
        )

        columns = (
            "name",
            "size",
            "type"
        )

        self.tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading(
            "name",
            text="File Name"
        )

        self.tree.heading(
            "size",
            text="Size"
        )

        self.tree.heading(
            "type",
            text="Type"
        )

        self.tree.column(
            "name",
            width=450
        )

        self.tree.column(
            "size",
            width=120,
            anchor="center"
        )

        self.tree.column(
            "type",
            width=120,
            anchor="center"
        )

        scrollbar = ttk.Scrollbar(
            list_frame,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.refresh_list()

        # Double click = export
        self.tree.bind(
            "<Double-1>",
            lambda event: self.export_file()
        )

    # ========================================================
    # REFRESH FILE LIST
    # ========================================================

    def refresh_list(self):

        if not hasattr(self, "tree"):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        for index, file_info in enumerate(
            self.manifest.get("files", [])
        ):

            name = file_info["name"]
            size = file_info["size"]
            extension = file_info["extension"]

            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    name,
                    self.format_size(size),
                    extension
                )
            )

    # ========================================================
    # FORMAT FILE SIZE
    # ========================================================

    @staticmethod
    def format_size(size):

        if size < 1024:
            return f"{size} B"

        if size < 1024 ** 2:
            return f"{size / 1024:.1f} KB"

        if size < 1024 ** 3:
            return f"{size / (1024 ** 2):.1f} MB"

        return f"{size / (1024 ** 3):.1f} GB"

    # ========================================================
    # ADD FILES
    # ========================================================

    def add_files(self):

        paths = filedialog.askopenfilenames(
            title="Select files to add"
        )

        if not paths:
            return

        added = 0

        for path in paths:

            try:

                self.encrypt_file(path)

                added += 1

            except Exception as e:

                messagebox.showerror(
                    "Error",
                    f"File add nahi ho payi:\n{path}\n\n{e}"
                )

        self.save_current_manifest()
        self.refresh_list()

        if added:
            messagebox.showinfo(
                "Files Added",
                f"{added} file(s) securely vault mein add ho gayi."
            )

    # ========================================================
    # ENCRYPT FILE
    # ========================================================

    def encrypt_file(self, original_path):

        original_path = Path(original_path)

        # File read
        with open(original_path, "rb") as f:
            data = f.read()

        # Generate random internal filename
        internal_name = str(uuid.uuid4()) + ".vault"

        encrypted_path = VAULT_DIR / internal_name

        # Encrypt
        encrypted_data = self.fernet.encrypt(data)

        # Write encrypted data
        with open(encrypted_path, "wb") as f:
            f.write(encrypted_data)

        # Add metadata
        file_info = {
            "id": internal_name,
            "name": original_path.name,
            "size": len(data),
            "extension": original_path.suffix.lower(),
        }

        self.manifest["files"].append(
            file_info
        )

        # IMPORTANT:
        # Original file automatically delete nahi hoti.
        # User manually delete kar sakta hai after checking vault.

    # ========================================================
    # EXPORT FILE
    # ========================================================

    def export_file(self):

        selection = self.tree.selection()

        if not selection:

            messagebox.showwarning(
                "No File Selected",
                "Pehle koi file select karo."
            )

            return

        index = int(selection[0])

        file_info = self.manifest["files"][index]

        internal_name = file_info["id"]
        original_name = file_info["name"]

        encrypted_path = VAULT_DIR / internal_name

        if not encrypted_path.exists():

            messagebox.showerror(
                "Error",
                "Encrypted file vault mein nahi mili."
            )

            return

        destination = filedialog.asksaveasfilename(
            title="Export File",
            initialfile=original_name
        )

        if not destination:
            return

        try:

            with open(encrypted_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self.fernet.decrypt(
                encrypted_data
            )

            with open(destination, "wb") as f:
                f.write(decrypted_data)

            messagebox.showinfo(
                "Export Successful",
                f"File successfully export ho gayi:\n\n{destination}"
            )

        except InvalidToken:

            messagebox.showerror(
                "Error",
                "File decrypt nahi ho saki."
            )

        except Exception as e:

            messagebox.showerror(
                "Error",
                f"Export failed:\n{e}"
            )

    # ========================================================
    # DELETE FILE
    # ========================================================

    def delete_file(self):

        selection = self.tree.selection()

        if not selection:

            messagebox.showwarning(
                "No File Selected",
                "Pehle koi file select karo."
            )

            return

        index = int(selection[0])

        file_info = self.manifest["files"][index]

        name = file_info["name"]

        answer = messagebox.askyesno(
            "Confirm Delete",
            f"'{name}' ko vault se permanently delete karna hai?"
        )

        if not answer:
            return

        internal_name = file_info["id"]

        encrypted_path = VAULT_DIR / internal_name

        try:

            if encrypted_path.exists():
                encrypted_path.unlink()

            self.manifest["files"].pop(index)

            self.save_current_manifest()

            self.refresh_list()

            messagebox.showinfo(
                "Deleted",
                "File vault se delete ho gayi."
            )

        except Exception as e:

            messagebox.showerror(
                "Error",
                f"Delete failed:\n{e}"
            )

    # ========================================================
    # SAVE MANIFEST
    # ========================================================

    def save_current_manifest(self):

        save_manifest(
            self.fernet,
            self.manifest
        )

    # ========================================================
    # LOCK VAULT
    # ========================================================

    def lock_vault(self):

        # Memory se encryption key hata dete hain
        self.fernet = None
        self.manifest = None

        self.show_login_screen()


# ============================================================
# START APPLICATION
# ============================================================

def main():

    root = tk.Tk()

    app = SecureVaultApp(root)

    root.mainloop()


if __name__ == "__main__":
    main()
