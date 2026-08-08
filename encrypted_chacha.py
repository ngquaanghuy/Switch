# Encrypted by Switch (chacha20) — run with: python3 this_file.py
# Requires: pip install cryptography
import sys

try:
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print('Error: "cryptography" package not found.', file=sys.stderr)
    print('Install it with: pip install cryptography', file=sys.stderr)
    sys.exit(1)

_ct = base64.b64decode("1gcFhmt6/GcKtmTfCdrA/QFUW3+01YPpEGM8ymRUHA89BCuxEg==")
_key = base64.b64decode("bsGQMNn0hMH0r6HLb4XHeRW0y5VqXmraT0fB9BWxvWM=")
_nonce = base64.b64decode("H6RzruTApCuk3E8x")

try:
    _box = ChaCha20Poly1305(_key)
    _pt = _box.decrypt(_nonce, _ct, None)
    # finalize handled internally by decrypt()
    exec(_pt.decode('utf-8'))
except (ValueError, Exception) as e:
    print(f'Error: decryption failed — {e}', file=sys.stderr)
    print('The file may have been encrypted with a different key.', file=sys.stderr)
    sys.exit(1)
