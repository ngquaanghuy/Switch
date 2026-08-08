# Encrypted by Switch (aes-256) — run with: python3 this_file.py
# Requires: pip install cryptography
import sys

try:
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    print('Error: "cryptography" package not found.', file=sys.stderr)
    print('Install it with: pip install cryptography', file=sys.stderr)
    sys.exit(1)

_ct = base64.b64decode("iZh71GUNcZpM19WyfqTVt6vNxRifJH1Zz3rRBHKyhT4NmYiIGfmYOFWoDvJpKguaueOzJZgMBE5BAeCP97Fl9w==")
_key = base64.b64decode("Z32+Bqc2Fki7IgNVfhjvNBazUwW64nyA6F61ZD3olpQ=")
_iv  = base64.b64decode("6263Zvdjp1aY7xBbetUCxg==")

try:
    _cipher = Cipher(algorithms.AES(_key), modes.CBC(_iv))
    _dec = _cipher.decryptor()
    _pt = _dec.update(_ct) + _dec.finalize()
    _unpad = sym_padding.PKCS7(128).unpadder()
    _pt = _unpad.update(_pt) + _unpad.finalize()
    exec(_pt.decode('utf-8'))
except ValueError as e:
    print(f'Error: decryption failed — {e}', file=sys.stderr)
    print('The file may have been encrypted with a different key.', file=sys.stderr)
    sys.exit(1)
