from PIL import Image, ImageTk
import numpy as np
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

# Global Variables
selected_image_path = None
ENCRYPTION_PASSWORD = "your_secure_password"

# GUI Setup
root = tk.Tk()
root.title("Image Encryption & Decryption")
root.geometry("600x500")

# Function to Select Image
def select_image():
    global selected_image_path
    file_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.jpg;*.png;*.bmp")])
    if file_path:
        selected_image_path = file_path
        display_image(file_path)
        messagebox.showinfo("Selected Image", f"File Selected: {os.path.basename(file_path)}")

# Function to Display Image in GUI
def display_image(image_path):
    image = Image.open(image_path)
    image = image.resize((250, 250))  
    img_display = ImageTk.PhotoImage(image)

    img_label.config(image=img_display)
    img_label.image = img_display  

# Function to Generate Encryption Key
def generate_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)  # Generate random salt for encryption
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# Function to Encrypt Image
def encrypt_image():
    global selected_image_path
    if not selected_image_path:
        messagebox.showerror("Error", "Please select an image first.")
        return
    
    image = Image.open(selected_image_path)
    image_array = np.array(image)
    
    # Generate Encryption Key
    key, salt = generate_key(ENCRYPTION_PASSWORD)
    
    # Convert Image Array to Bytes
    image_data = image_array.tobytes()
    nonce = os.urandom(16)

    # Apply AES Encryption
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_image_data = encryptor.update(image_data) + encryptor.finalize()

    # Save Encrypted Image
    encrypted_file_path = selected_image_path + ".encrypted"
    with open(encrypted_file_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(encrypted_image_data)

    # Store Image Metadata
    metadata = {"size": image.size, "bands": len(image.getbands())}
    with open(encrypted_file_path + ".meta", "w") as f:
        json.dump(metadata, f)

    messagebox.showinfo("Success", "Image encrypted successfully!")

# Function to Decrypt Image
def decrypt_image():
    encrypted_file_path = filedialog.askopenfilename(title="Select Encrypted Image", filetypes=[("Encrypted Files", "*.encrypted")])
    if not encrypted_file_path:
        messagebox.showerror("Error", "Please select an encrypted file first.")
        return
    
    # Load Encrypted Data
    with open(encrypted_file_path, "rb") as f:
        salt = f.read(16)
        nonce = f.read(16)
        encrypted_image_data = f.read()

    # Load Metadata
    try:
        with open(encrypted_file_path + ".meta", "r") as f:
            metadata = json.load(f)
    except FileNotFoundError:
        messagebox.showerror("Error", "Metadata file is missing. Decryption failed.")
        return

    # Regenerate Key Using Stored Salt
    key, _ = generate_key(ENCRYPTION_PASSWORD, salt)

    # Apply AES Decryption
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_image_data = decryptor.update(encrypted_image_data) + decryptor.finalize()
    
    # Convert Back to Image
    image_shape = (metadata["size"][1], metadata["size"][0], metadata["bands"])
    decrypted_image_array = np.frombuffer(decrypted_image_data, dtype=np.uint8).reshape(image_shape)
    decrypted_image = Image.fromarray(decrypted_image_array)

    decrypted_image.show()
    messagebox.showinfo("Success", "Image decrypted successfully!")

# GUI Elements
select_button = tk.Button(root, text="Select Image", command=select_image)
select_button.pack(pady=10)

encrypt_button = tk.Button(root, text="Encrypt Image", command=encrypt_image)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt Image", command=decrypt_image)
decrypt_button.pack(pady=10)

img_label = tk.Label(root)  
img_label.pack(pady=10)

# Run GUI
root.mainloop()
