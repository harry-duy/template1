# cipher/AES/aes.py
# AES-128 implementation (CBC mode, PKCS#7), pure Python

import os
from typing import List
from .utils import pkcs7_pad, pkcs7_unpad

# S-box
s_box = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# inverse S-box
inv_s_box = [0]*256
for i,v in enumerate(s_box):
    inv_s_box[v] = i

# Rcon
Rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def sub_word(word: List[int]) -> List[int]:
    return [s_box[b] for b in word]

def rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]

def xor_words(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]

def key_expansion(key: bytes) -> List[List[int]]:
    Nk = 4
    Nb = 4
    Nr = 10
    key_symbols = list(key)
    if len(key_symbols) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    w = [key_symbols[i*4:(i+1)*4] for i in range(Nk)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1].copy()
        if i % Nk == 0:
            temp = xor_words(sub_word(rot_word(temp)), [Rcon[i//Nk],0,0,0])
        w.append(xor_words(w[i-Nk], temp))
    round_keys = []
    for r in range(Nr+1):
        rk = []
        for c in range(4):
            rk += w[r*4 + c]
        round_keys.append(rk)
    return round_keys

def add_round_key(state: List[int], round_key: List[int]) -> List[int]:
    return [s ^ k for s, k in zip(state, round_key)]

def sub_bytes(state: List[int]) -> List[int]:
    return [s_box[b] for b in state]

def inv_sub_bytes(state: List[int]) -> List[int]:
    return [inv_s_box[b] for b in state]

def shift_rows(state: List[int]) -> List[int]:
    m = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            m[r][c] = state[c*4 + r]
    for r in range(1,4):
        m[r] = m[r][r:] + m[r][:r]
    out = []
    for c in range(4):
        for r in range(4):
            out.append(m[r][c])
    return out

def inv_shift_rows(state: List[int]) -> List[int]:
    m = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            m[r][c] = state[c*4 + r]
    for r in range(1,4):
        m[r] = m[r][-r:] + m[r][:-r]
    out = []
    for c in range(4):
        for r in range(4):
            out.append(m[r][c])
    return out

def xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff

def mul(a: int, b: int) -> int:
    res = 0
    for i in range(8):
        if b & 1:
            res ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xff
        if hi_bit:
            a ^= 0x1b
        b >>= 1
    return res

def mix_single_column(col: List[int]) -> List[int]:
    a = col
    return [
        mul(0x02, a[0]) ^ mul(0x03, a[1]) ^ a[2] ^ a[3],
        a[0] ^ mul(0x02, a[1]) ^ mul(0x03, a[2]) ^ a[3],
        a[0] ^ a[1] ^ mul(0x02, a[2]) ^ mul(0x03, a[3]),
        mul(0x03, a[0]) ^ a[1] ^ a[2] ^ mul(0x02, a[3])
    ]

def mix_columns(state: List[int]) -> List[int]:
    out = [0]*16
    for c in range(4):
        col = [state[c*4 + r] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            out[c*4 + r] = mixed[r]
    return out

def inv_mix_single_column(col: List[int]) -> List[int]:
    a = col
    return [
        mul(0x0e,a[0]) ^ mul(0x0b,a[1]) ^ mul(0x0d,a[2]) ^ mul(0x09,a[3]),
        mul(0x09,a[0]) ^ mul(0x0e,a[1]) ^ mul(0x0b,a[2]) ^ mul(0x0d,a[3]),
        mul(0x0d,a[0]) ^ mul(0x09,a[1]) ^ mul(0x0e,a[2]) ^ mul(0x0b,a[3]),
        mul(0x0b,a[0]) ^ mul(0x0d,a[1]) ^ mul(0x09,a[2]) ^ mul(0x0e,a[3])
    ]

def inv_mix_columns(state: List[int]) -> List[int]:
    out = [0]*16
    for c in range(4):
        col = [state[c*4 + r] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            out[c*4 + r] = mixed[r]
    return out

def encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = list(block)
    state = add_round_key(state, round_keys[0])
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return bytes(state)

def decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = list(block)
    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for r in range(9, 0, -1):
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return bytes(state)

# CBC mode: encrypt plaintext bytes with key bytes -> returns iv + ciphertext
def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    round_keys = key_expansion(key)
    plaintext_padded = pkcs7_pad(plaintext, 16)
    iv = os.urandom(16)
    prev = iv
    ciphertext = b''
    for i in range(0, len(plaintext_padded), 16):
        block = plaintext_padded[i:i+16]
        xored = bytes(a ^ b for a,b in zip(block, prev))
        enc = encrypt_block(xored, round_keys)
        ciphertext += enc
        prev = enc
    return iv + ciphertext

def decrypt_bytes(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(iv_and_ciphertext) < 16 or (len(iv_and_ciphertext) - 16) % 16 != 0:
        raise ValueError("Invalid ciphertext length")
    round_keys = key_expansion(key)
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    prev = iv
    plaintext_padded = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = decrypt_block(block, round_keys)
        plain_block = bytes(a ^ b for a,b in zip(dec, prev))
        plaintext_padded += plain_block
        prev = block
    return pkcs7_unpad(plaintext_padded)

# --- helper: parse key (string) -> bytes (16 bytes) ---
def parse_key(key_str: str) -> bytes:
    if key_str is None:
        raise ValueError("Key required")
    k = key_str.strip()
    if len(k) == 32 and all(c in "0123456789abcdefABCDEF" for c in k):
        return bytes.fromhex(k)
    else:
        kb = k.encode()
        if len(kb) != 16:
            raise ValueError("Key must be 16-byte string or 32 hex chars")
        return kb
def save_key_to_file(key_str: str, path: str) -> None:
    """
    Save AES key string to file.
    The key is saved exactly as user inputs.
    """
    if key_str is None or key_str.strip() == "":
        raise ValueError("Key is empty, cannot save.")
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(key_str.strip())


def load_key_from_file(path: str) -> str:
    """
    Load AES key string from a file.
    """
    if not os.path.exists(path):
        raise FileNotFoundError("Key file not found: " + path)

    with open(path, "r", encoding="utf-8") as f:
        key_str = f.read().strip()

    if key_str == "":
        raise ValueError("Key file is empty.")

    return key_str
# Optional class wrapper with file helpers
class AESCipher:
    def __init__(self):
        pass

    # =============================
    # SAVE / LOAD KEY from file
    # =============================
    def save_key(self, key_str: str, file_path: str):
        save_key_to_file(key_str, file_path)

    def load_key(self, file_path: str) -> str:
        return load_key_from_file(file_path)

    # Encrypt + Decrypt (giữ nguyên)
    def encrypt_bytes_with_key(self, data: bytes, key_str: str) -> bytes:
        key = parse_key(key_str)
        return encrypt_bytes(data, key)

    def decrypt_bytes_with_key(self, iv_and_ciphertext: bytes, key_str: str) -> bytes:
        key = parse_key(key_str)
        return decrypt_bytes(iv_and_ciphertext, key)

    # =============================
    # Encrypt using KEY FILE
    # =============================
    def encrypt_with_key_file(self, data: bytes, key_file: str) -> bytes:
        key_str = load_key_from_file(key_file)
        return self.encrypt_bytes_with_key(data, key_str)

    # Decrypt using KEY FILE
    def decrypt_with_key_file(self, data: bytes, key_file: str) -> bytes:
        key_str = load_key_from_file(key_file)
        return self.decrypt_bytes_with_key(data, key_str)

    # =============================
    # FILE ENCRYPT / DECRYPT
    # =============================
    def encrypt_file(self, input_path: str, output_path: str, key_str: str):
        with open(input_path, "rb") as f:
            plain = f.read()
        enc = self.encrypt_bytes_with_key(plain, key_str)
        with open(output_path, "wb") as f:
            f.write(enc)

    def decrypt_file(self, input_path: str, output_path: str, key_str: str):
        with open(input_path, "rb") as f:
            data = f.read()
        plain = self.decrypt_bytes_with_key(data, key_str)
        with open(output_path, "wb") as f:
            f.write(plain)

    # Encrypt/Decrypt bằng KEY FILE
    def encrypt_file_keyfile(self, input_path: str, output_path: str, key_file: str):
        key_str = load_key_from_file(key_file)
        self.encrypt_file(input_path, output_path, key_str)

    def decrypt_file_keyfile(self, input_path: str, output_path: str, key_file: str):
        key_str = load_key_from_file(key_file)
        self.decrypt_file(input_path, output_path, key_str)
