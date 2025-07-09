import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# Encryption helpers
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(message: str, password: str) -> (bytes, bytes):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return salt + encrypted  # prepend salt to encrypted message

def decrypt_message(data: bytes, password: str) -> str:
    salt = data[:16]
    encrypted = data[16:]
    key = generate_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()

# Binary conversion
def to_bin(data_bytes):
    return ''.join([format(byte, '08b') for byte in data_bytes])

def from_bin(binary_data):
    byte_array = [int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8)]
    return bytes(byte_array)

# LSB Encoding
def encode_lsb(img_path, data_bytes, output_path):
    img = Image.open(img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    binary_data = to_bin(data_bytes) + '1111111111111110'  # delimiter
    data_index = 0
    new_pixels = []

    for pixel in list(img.getdata()):
        r, g, b = pixel
        if data_index < len(binary_data):
            r = r & ~1 | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            g = g & ~1 | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            b = b & ~1 | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path)
    return True

# LSB Decoding
def decode_lsb(img_path):
    img = Image.open(img_path)
    binary_data = ''
    for pixel in img.getdata():
        for color in pixel[:3]:
            binary_data += str(color & 1)
            if binary_data[-16:] == '1111111111111110':
                message_bin = binary_data[:-16]
                return from_bin(message_bin)
    return b''

# GUI logic
def select_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp")])
    return file_path

def save_image():
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
    return file_path

def hide_message():
    img_path = select_image()
    if not img_path:
        return
    message = text_input.get("1.0", tk.END).strip()
    password = password_input.get().strip()
    if not message or not password:
        messagebox.showwarning("Input Error", "Enter both message and password.")
        return
    output_path = save_image()
    try:
        encrypted_data = encrypt_message(message, password)
        if encode_lsb(img_path, encrypted_data, output_path):
            messagebox.showinfo("Success", f"Message embedded in {output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def extract_message():
    img_path = select_image()
    if not img_path:
        return
    password = password_input.get().strip()
    if not password:
        messagebox.showwarning("Input Error", "Enter password to decrypt the message.")
        return
    try:
        encrypted_data = decode_lsb(img_path)
        if not encrypted_data:
            raise ValueError("No hidden message found or incorrect format.")
        decrypted = decrypt_message(encrypted_data, password)
        text_input.delete("1.0", tk.END)
        text_input.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed: " + str(e))

# GUI Setup
root = tk.Tk()
root.title("StegTool - LSB with Encryption")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

tk.Label(frame, text="Message:").pack()
text_input = tk.Text(frame, height=10, width=50)
text_input.pack(pady=5)

tk.Label(frame, text="Password:").pack()
password_input = tk.Entry(frame, show="*")
password_input.pack(pady=5)

btn_hide = tk.Button(frame, text="Hide Message", command=hide_message)
btn_hide.pack(pady=5)

btn_extract = tk.Button(frame, text="Extract Message", command=extract_message)
btn_extract.pack(pady=5)

root.mainloop()
