from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def derive_key(password):
    salt = b'salt_123'  # Change this to a unique value for your application
    kdf = PBKDF2HMAC(
        algorithm=algorithms.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt(note, password):
    key = derive_key(password)
    cipher = Cipher(algorithms.AES(key), modes.GCM())
    encryptor = cipher.encryptor()
    encrypted_note = encryptor.update(note.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(encryptor.tag + encrypted_note)

def decrypt(encrypted_note, password):
    key = derive_key(password)
    data = base64.urlsafe_b64decode(encrypted_note)
    cipher = Cipher(algorithms.AES(key), modes.GCM(data[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_note = decryptor.update(data[16:]) + decryptor.finalize()
    return decrypted_note.decode()

# Example usage
password = 'your_secret_key'  # Replace with a strong secret key
note = 'This is a secret note.'

# Encrypt
encrypted_note = encrypt(note, password)
print(f'Encrypted Note: {encrypted_note.decode()}')

# Decrypt
decrypted_note = decrypt(encrypted_note, password)
print(f'Decrypted Note: {decrypted_note}')
