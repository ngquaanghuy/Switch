# Encrypted by Switch (aes-256-gcm) — run with: python3 this_file.py
# Requires: pip install cryptography
import sys

try:
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print('Error: "cryptography" package not found.', file=sys.stderr)
    print('Install it with: pip install cryptography', file=sys.stderr)
    sys.exit(1)

_ct = base64.b64decode("LiZTH7v3zV7tZcPJAgaf1NjQLFMXV+KnpD6fl7rXSQi4DM8XaQ==")
_key = base64.b64decode("+4F6Kr29lt67jv25k9R7JwxI/AeJ6I0z1aaKv0upJC4=")
_iv  = base64.b64decode("hiKjIDqofA0MnUQB")

try:
    _box = AESGCM(_key)
    _pt = _box.decrypt(_iv, _ct, None)
    exec(_pt.decode('utf-8'))
except ValueError as e:
    print(f'Error: decryption failed — {e}', file=sys.stderr)
    print('The file may have been encrypted with a different key.', file=sys.stderr)
    sys.exit(1)
