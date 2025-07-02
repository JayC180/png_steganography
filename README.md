# About
This is a tools for hiding data in png images using AES, RSA, and LSB steganography with spread-spectrum. Designed for securely sending information to others.

## Example
- The image on the right embeds the secret `"This is a test file."`

| Original | Embedded |
|---|---|
| ![orig](assets/img.png) | ![embed](assets/embed.png) |

## Usage

1. Install dependencies:
```bash
# Install with pip:
pip install -r requirements.txt

# Or with uv:
uv pip install -r pyproject.toml
```
2. Generate RSA key pairs:
```bash
mkdir keys
main.py -g -o <output_directory> # -o is optional
```
3. Encode a file:
```bash
main.py -e -i <path_to_secret_file> -p <path_to_png> --public-key <path_to_recipient_public_key> -o <output_directory> # -o is optional
```
4. Decode a file:
```bash
main.py -d -p <path_to_png> --private-key <path_to_your_private_key> -o <output_directory> # -o is optional
```
