import base64
import os
import tkinter as tk
from tkinter import messagebox

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    if not password:
        raise ValueError("Zadej heslo")
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = b"v1" + salt + nonce + ciphertext
    return base64.urlsafe_b64encode(blob).decode("utf-8")


def decrypt_text(token: str, password: str) -> str:
    if not password:
        raise ValueError("Zadej heslo")
    blob = base64.urlsafe_b64decode(token.encode("utf-8"))
    if blob[:2] != b"v1":
        raise ValueError("Neplatný formát")
    salt = blob[2:18]
    nonce = blob[18:30]
    ciphertext = blob[30:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def encrypt():
    try:
        output.delete("1.0", tk.END)
        output.insert(tk.END, encrypt_text(input_text.get("1.0", tk.END).strip(), password.get()))
    except Exception as e:
        messagebox.showerror("Chyba", str(e))


def decrypt():
    try:
        output.delete("1.0", tk.END)
        output.insert(tk.END, decrypt_text(input_text.get("1.0", tk.END).strip(), password.get()))
    except Exception as e:
        messagebox.showerror("Chyba", str(e))


root = tk.Tk()
root.title("TextCryptAES")

tk.Label(root, text="Heslo:").grid(row=0, column=0, sticky="w", padx=8, pady=5)
password = tk.Entry(root, show="*", width=40)
password.grid(row=0, column=1, padx=8, pady=5)

tk.Label(root, text="Vstupní text / šifra:").grid(row=1, column=0, sticky="w", padx=8)
input_text = tk.Text(root, height=7, width=70)
input_text.grid(row=2, column=0, columnspan=2, padx=8)

tk.Button(root, text="Šifrovat →", command=encrypt).grid(row=3, column=0, padx=8, pady=6, sticky="w")
tk.Button(root, text="← Dešifrovat", command=decrypt).grid(row=3, column=1, padx=8, pady=6, sticky="w")

tk.Label(root, text="Výstup:").grid(row=4, column=0, sticky="w", padx=8)
output = tk.Text(root, height=7, width=70)
output.grid(row=5, column=0, columnspan=2, padx=8, pady=5)

root.mainloop()
