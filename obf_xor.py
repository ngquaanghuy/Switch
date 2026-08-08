from itertools import cycle
print(bytes((a ^ b for a, b in zip([182, 191, 146, 182, 145, 250, 169, 181, 140, 182, 154], cycle([254, 218])))).decode())
