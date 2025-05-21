from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.image import Image as KivyImage
import numpy as np
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import hashlib
from PIL import Image

# Global Variable for Encryption Password
ENCRYPTION_PASSWORD = "your_secure_password"

class EncryptionApp(App):
    def build(self):
        # Main layout
        layout = BoxLayout(orientation='vertical')

        # Updated File Chooser with Image Filtering & Correct Path
        self.file_chooser = FileChooserIconView(
            filters=["*.png", "*.jpg", "*.bmp"],  # Show only image files
            path=os.path.join(os.path.expanduser("~"), "Pictures")  # Start in the Pictures folder
        )
        layout.add_widget(self.file_chooser)

        # Buttons for Encrypt and Decrypt
        btn_encrypt = Button(text="Encrypt Image", on_press=self.encrypt_image)
        btn_decrypt = Button(text="Decrypt Image", on_press=self.decrypt_image)

        layout.add_widget(btn_encrypt)
        layout.add_widget(btn_decrypt)

        # Display area for the selected image
        self.img_display = KivyImage()
        layout.add_widget(self.img_display)

        return layout

    def encrypt_image(self, instance):
        selected_file = self.file_chooser.selection
        if not selected_file:
            print("No file selected.")
            return
        
        file_path = selected_file[0]
        image = Image.open(file_path)
        image_array = np.array(image)

        # Generate encryption key
        key, salt = self.generate_key(ENCRYPTION_PASSWORD)

        # Encrypt image
        image_data = image_array.tobytes()
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_image_data = encryptor.update(image_data) + encryptor.finalize()

        # Save encrypted image
        encrypted_file_path = file_path + ".encrypted"
        metadata_file_path = encrypted_file_path + ".meta"

        with open(encrypted_file_path, "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(encrypted_image_data)

        # Store Image Metadata (to ensure proper decryption)
        metadata = {"size": image.size, "bands": len(image.getbands())}
        with open(metadata_file_path, "w") as f:
            json.dump(metadata, f)

        print(f"Image encrypted and metadata saved successfully at:\n{metadata_file_path}")

    def decrypt_image(self, instance):
        selected_file = self.file_chooser.selection
        if not selected_file:
            print("No file selected.")
            return

        file_path = selected_file[0]
        metadata_file_path = file_path + ".meta"

        # Ensure metadata file exists before proceeding
        if not os.path.exists(metadata_file_path):
            print(f"Metadata file not found: {metadata_file_path}")
            print("Ensure the encrypted image and metadata file are in the same folder.")
            return

        # Load encrypted data
        with open(file_path, "rb") as f:
            salt = f.read(16)
            nonce = f.read(16)
            encrypted_image_data = f.read()

        # Load metadata
        with open(metadata_file_path, "r") as f:
            metadata = json.load(f)

        # Regenerate encryption key
        key, _ = self.generate_key(ENCRYPTION_PASSWORD, salt)

        # Decrypt image
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_image_data = decryptor.update(encrypted_image_data) + decryptor.finalize()

        # Convert back to image
        image_shape = (metadata["size"][1], metadata["size"][0], metadata["bands"])
        decrypted_image_array = np.frombuffer(decrypted_image_data, dtype=np.uint8).reshape(image_shape)
        decrypted_image = Image.fromarray(decrypted_image_array)

        # Save and display decrypted image
        decrypted_file_path = file_path + "_decrypted.png"
        decrypted_image.save(decrypted_file_path)

        self.img_display.source = decrypted_file_path
        self.img_display.reload()

        print(f"Image decrypted successfully! Saved at:\n{decrypted_file_path}")

    def generate_key(self, password, salt=None):
        if not salt:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

if __name__ == "__main__":
    EncryptionApp().run()
