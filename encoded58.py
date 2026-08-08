# Encoded by Switch — run with: python this_file.py
_sw = "7v3VzRi6TvHY4MGVEv2RDxxKw2hiR"
_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_n = 0
_zeros = 0
for _c in _sw:
    if _c == '1' and _n == 0:
        _zeros += 1
        continue
    _n = _n * 58 + _alphabet.index(_c)
if _n or _zeros:
    exec(b'\x00' * _zeros + _n.to_bytes(max(1, (_n.bit_length() + 7) // 8), 'big'))
