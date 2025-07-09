import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import os

def to_bin(data):
    return ''.join([format(ord(i), '08b') for i in data])

def from_bin(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join([chr(int(b, 2)) for b in chars])

def encode_lsb(img_path, message, output_path):
    img = Image.open(img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    binary_msg = to_bin(message) + '1111111111111110'  # Delimiter
    data_index = 0
    new_pixels = []

    for pixel in list(img.getdata()):
        r, g, b = pixel
        if data_index < len(binary_msg):
            r = r & ~1 | int(binary_msg[data_index])
            data_index += 1
        if data_index < len(binary_msg):
            g = g & ~1 | int(binary_msg[data_index])
            data_index += 1
        if data_index < len(binary_msg):
            b = b & ~1 | int(binary_msg[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path)
    return True

def decode_lsb(img_path):
    img = Image.open(img_path)
    binary_data = ''
    for pixel in img.getdata():
        for color in pixel[:3]:
            binary_data += str(color & 1)
            if binary_data[-16:] == '1111111111111110':
                message_bin = binary_data[:-16]
                return from_bin(message_bin)
    return "No hidden message found."

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
    if not message:
        messagebox.showwarning("Input Error", "Enter a message to hide.")
        return
    output_path = save_image()
    if encode_lsb(img_path, message, output_path):
        messagebox.showinfo("Success", f"Message embedded in {output_path}")

def extract_message():
    img_path = select_image()
    if not img_path:
        return
    message = decode_lsb(img_path)
    text_input.delete("1.0", tk.END)
    text_input.insert(tk.END, message)

# GUI setup
root = tk.Tk()
root.title("StegTool - LSB")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

text_input = tk.Text(frame, height=10, width=50)
text_input.pack(pady=10)

btn_hide = tk.Button(frame, text="Hide Message", command=hide_message)
btn_hide.pack(pady=5)

btn_extract = tk.Button(frame, text="Extract Message", command=extract_message)
btn_extract.pack(pady=5)

root.mainloop()
