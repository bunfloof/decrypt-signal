#!/usr/bin/env python3
"""Decrypt a Signal Desktop v2 attachment.

Edit the two constants below, then run from the directory containing the
encrypted file. The decrypted file is written into the same directory.

Signal v2 on-disk format:
    [16-byte IV] [AES-256-CBC ciphertext] [32-byte HMAC-SHA256]

The base64-decoded key is 64 bytes: first 32 = AES key, last 32 = HMAC key.
HMAC covers IV + ciphertext. After AES decrypt + PKCS7 unpad, Signal also
appends bucket padding (zeros) which we trim using the size from the URL.
"""

import base64
import hmac
import hashlib
import urllib.parse
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

ENC_FILENAME = "c1f5626b6e9d23c8b70fa510c8862bd0d99bc6d4755727ea6ed0e86a15b60572"
ATTACHMENT_URL = "attachment://v2/c1/c1f5626b6e9d23c8b70fa510c8862bd0d99bc6d4755727ea6ed0e86a15b60572?key=gntpg7%2FtaEZHYCrq%2Bq3q5V2ff7Aqzu1%2FGlzd03DEYtLZP5F1dHOWCrDM7Nar3Pm%2BXP5zcoIh1r7G13kL14Mjdg%3D%3D&size=1927804&contentType=image%2Fjpeg&disposition=temporary"

here = Path(__file__).resolve().parent
enc_path = here / ENC_FILENAME

params = urllib.parse.parse_qs(ATTACHMENT_URL.split("?", 1)[1])
key = base64.b64decode(params["key"][0])
real_size = int(params["size"][0])
assert len(key) == 64, f"Expected 64-byte combined key, got {len(key)}"
aes_key, mac_key = key[:32], key[32:]

blob = enc_path.read_bytes()
iv, ciphertext, file_mac = blob[:16], blob[16:-32], blob[-32:]

expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
if not hmac.compare_digest(expected_mac, file_mac):
    print("WARNING: HMAC mismatch — wrong key, or file is corrupted.")

decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
padded = decryptor.update(ciphertext) + decryptor.finalize()
unpadder = PKCS7(128).unpadder()
plaintext = unpadder.update(padded) + unpadder.finalize()

plaintext = plaintext[:real_size]

if plaintext.startswith(b"\xff\xd8\xff"):
    ext = "jpg"
elif plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
    ext = "png"
elif plaintext.startswith(b"GIF8"):
    ext = "gif"
elif plaintext[:4] == b"RIFF" and plaintext[8:12] == b"WEBP":
    ext = "webp"
elif plaintext.startswith(b"%PDF"):
    ext = "pdf"
elif plaintext[4:8] == b"ftyp":
    ext = "mp4"
elif plaintext.startswith(b"\x1aE\xdf\xa3"):
    ext = "mkv"
else:
    ext = "bin"

out_path = here / f"{enc_path.stem}.decrypted.{ext}"
out_path.write_bytes(plaintext)
print(f"Wrote {len(plaintext):,} bytes → {out_path.name}")