import zlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

def aes_encrypt(file_path):
    # compress, gen aes-256 + iv, enc with aes-cbc
    backend = default_backend()

    with open(file_path, "rb") as f:
        data = f.read()

    compressed_data = zlib.compress(data)

    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # 128-bit IV for CBC

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(compressed_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, key + iv  

def aes_decrypt(encrypted_data, key_iv):
    key = key_iv[:32]
    iv = key_iv[32:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return zlib.decompress(data)

def rsa_encrypt(header_bytes, pub_key_path):
    with open(pub_key_path, "rb") as key_file:
        pub_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    encrypted = pub_key.encrypt(
        header_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt(encrypted_header_bytes, priv_key_path):
    with open(priv_key_path, "rb") as key_file:
        priv_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Add password bytes here if key is encrypted
            backend=default_backend()
        )

    decrypted = priv_key.decrypt(
        encrypted_header_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


def generate_keys(output_dir='.'):
    if not os.path.isdir(output_dir):
        raise FileNotFoundError(f"Targeted output directory does not exist: {output_dir}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    priv_path = os.path.join(output_dir, "private_key.pem")
    pub_path = os.path.join(output_dir, "public_key.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return priv_path, pub_path



