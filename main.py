import argparse
import random
import os
import sys
from hashlib import sha256
import numpy as np
import cv2
from crypto import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, generate_keys

def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def spread_bits(bits: str, scalar: int) -> str:
    return ''.join(bit * scalar for bit in bits)

def xor_with_prn(bits: str, seed: int) -> str:
    prng = random.Random(seed)
    prn_bits = ''.join(str(prng.randint(0,1)) for _ in range(len(bits)))
    return ''.join(str(int(b) ^ int(p)) for b, p in zip(bits, prn_bits))

def bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def despread_bits(spreaded_bits: str, scalar: int) -> str:
    return ''.join(spreaded_bits[i] for i in range(0, len(spreaded_bits), scalar))

# use hash as reproducible seed
def compute_seed_from_image(image_path):
    with open(image_path, 'rb') as f:
        img_bytes = f.read()
    hash_val = sha256(img_bytes).digest()
    return int.from_bytes(hash_val[:4], 'big')

def encode(image_path, file_path, out_path, pub_key):
    seed = compute_seed_from_image(image_path)
    prng = random.Random(seed)

    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)

    if img is None:
        raise ValueError("Failed to load image.")

    # to BGRA if needed
    if img.shape[2] == 3:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2BGRA)

    pixels = img.copy()
    height, width, _ = pixels.shape
    num_pixels = height * width

    encrypted_data, symmetric_key_iv = aes_encrypt(file_path)

    symmetric_key = symmetric_key_iv[:32] # aes-256 key
    iv = symmetric_key_iv[32:] # 128-bit iv for cbc

    data_len = len(encrypted_data)

    checksum = sha256(encrypted_data).digest()

    scalar = random.randint(2, 8)

    # Header content: seed (4 bytes) + scalar (1 byte) + data_len (4 bytes) + symmetric_key (32 bytes for AES-256) + iv (16 bytes) + checksum (32 bytes)
    header_plain = seed.to_bytes(4, 'big') + scalar.to_bytes(1, 'big') + data_len.to_bytes(4, 'big') + symmetric_key + iv + checksum
    rsa_encrypted_header = rsa_encrypt(header_plain, pub_key)

    # rsa_encrypted_header to bits (fixed header size)
    header_bits = bytes_to_bits(rsa_encrypted_header)
    header_bit_len = len(header_bits)

    # reserve first N pixels for header (1 bit per pixel, use LSB of red channel)
    if header_bit_len > num_pixels:
        raise ValueError("Image too small for header embedding.")

    # embed header (fixed location)
    for i in range(header_bit_len):
        y, x = divmod(i, width)
        bit = int(header_bits[i])
        if (pixels[y, x, 2] & 1) != bit:  # red
            pixels[y, x, 2] ^= 1

    # spread, mod payload
    payload_bits = bytes_to_bits(encrypted_data)
    spreaded_bits = spread_bits(payload_bits, scalar)
    modulated_bits = xor_with_prn(spreaded_bits, seed)

    # check capacity for payload
    available_pixels_for_payload = num_pixels - header_bit_len
    if len(modulated_bits) > available_pixels_for_payload:
        raise ValueError("Image not large enough to embed spread payload.")

    # shuffle pixel indices for payload embedding
    payload_indices = list(range(header_bit_len, num_pixels))
    prng.shuffle(payload_indices)

    # embed payload bits into red LSB
    for i, bit_char in enumerate(modulated_bits):
        idx = payload_indices[i]
        y, x = divmod(idx, width)
        bit = int(bit_char)
        if (pixels[y, x, 2] & 1) != bit:
            pixels[y, x, 2] ^= 1

    out_path = os.path.join(out_path, "embed.png")

    if os.path.exists(out_path):
        overwrite = input(f"File '{out_path}' exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            print("Embedding cancelled.")
            return

    cv2.imwrite(out_path, pixels)

    # print(f"seed: {seed}")
    # print(f"prng: {prng}")
    # print(f"scalar: {scalar}")
    # print(f"data_len: {data_len}")
    # print(f"header: {rsa_encrypted_header}")

    return

def decode(image_path, file_path, out_path, priv_key):
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("Failed to load image.")

    if img.shape[2] == 3:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2BGRA)
    pixels = img
    height, width, _ = pixels.shape
    num_pixels = height * width

    # get header: 4096 = 512 * 8
    rsa_header_bit_len = 512 * 8

    header_bits = []
    for i in range(rsa_header_bit_len):
        y, x = divmod(i, width)
        bit = pixels[y, x, 2] & 1
        header_bits.append(str(bit))
    header_bits = ''.join(header_bits)

    rsa_encrypted_header_bytes = bits_to_bytes(header_bits)

    header_plain = rsa_decrypt(rsa_encrypted_header_bytes, priv_key)

    # Parse header: seed (4), scalar (1), data_len (4), symmetric_key (32), iv (16),  checksum (32)
    seed = int.from_bytes(header_plain[:4], 'big')
    prng = random.Random(seed)
    scalar = header_plain[4]
    data_len = int.from_bytes(header_plain[5:9], 'big')
    # print(f"seed: {seed}")
    # print(f"prng: {prng}")
    # print(f"scalar: {scalar}")
    # print(f"data_len: {data_len}")
    # print(f"header: {rsa_encrypted_header_bytes}")
    symmetric_key = header_plain[9:41] # 32 bytes
    iv = header_plain[41:57] # 16 bytes
    checksum = header_plain[57:]

    # get spread & modded payload
    payload_bit_len = data_len * 8 * scalar
    available_payload_pixels = num_pixels - rsa_header_bit_len
    if payload_bit_len > available_payload_pixels:
        raise ValueError("Image does not contain enough pixels for payload.")

    payload_indices = list(range(rsa_header_bit_len, num_pixels))
    prng.shuffle(payload_indices)

    payload_bits = []
    for i in range(payload_bit_len):
        idx = payload_indices[i]
        y, x = divmod(idx, width)
        bit = pixels[y, x, 2] & 1
        payload_bits.append(str(bit))
    payload_bits = ''.join(payload_bits)

    demodulated_bits = xor_with_prn(payload_bits, seed)
    despreaded_bits = despread_bits(demodulated_bits, scalar)
    encrypted_data = bits_to_bytes(despreaded_bits)

    computed_checksum = sha256(encrypted_data).digest()
    if computed_checksum != checksum:
        raise ValueError("Checksum doesn't match.")

    decrypted_data = aes_decrypt(encrypted_data, symmetric_key + iv)

    out_path = os.path.join(out_path, "extract.txt")

    if os.path.exists(out_path):
        overwrite = input(f"File '{out_path}' exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            print("Extraction cancelled.")
            return

    with open(out_path, 'wb') as f:
        f.write(decrypted_data)

    return

def main():
    parser = argparse.ArgumentParser(description='stegnography tool that hides message in png files')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help='Embeds secret file into PNG. requires --input, --png, --public-key. --output-dir optional')
    group.add_argument('-d', '--decrypt', action='store_true', help='Gets secret file from encoded PNG. requires --png, --private-key. --output-dir optional')
    group.add_argument('-g', '--generate', action='store_true', help='Generate key pair. Can use --output-dir to specify output directory; defaults to current directory')

    parser.add_argument('-i', '--input', help='Path to input data/file')
    parser.add_argument('-p', '--png', help='Path to PNG file')
    parser.add_argument('--public-key', help='Path to receiver\'s public key')
    parser.add_argument('--private-key', help='Path to your own private key')
    parser.add_argument('-o', '--output-dir', default='.', help='Output directory for generated key pairs or encrypted/decrypted results')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.encrypt:
        if not (args.input and args.png and args.public_key):
            parser.error("Encryption requires --input, --png, and --public-key")
        encode(args.png, args.input, args.output_dir, args.public_key)
        print(f"Success! Output saved to {args.output_dir} as 'embed.png'")

    elif args.decrypt:
        if not (args.png and args.private_key):
            parser.error("Decryption requires --png and --private-key")
        decode(args.png, args.input, args.output_dir, args.private_key)
        print(f"Success! Output saved to {args.output_dir} as 'extracted.txt'")
    
    elif args.generate:
        priv, pub = generate_keys(args.output_dir)
        print(f"Private key saved to: {priv}")
        print(f"Public key saved to: {pub}")
        sys.exit(0)

if __name__ == "__main__":
    main()
