# cipher/DES/utils.py

def string_to_bits(s: str) -> list:
    """Chuyển string thành list bits"""
    bits = []
    for ch in s:
        byte_val = ord(ch)
        for i in range(8):
            bits.append((byte_val >> (7 - i)) & 1)
    return bits


def bits_to_string(bits: list) -> str:
    """Chuyển list bits thành string"""
    chars = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(bits):
                byte_val = (byte_val << 1) | bits[i + j]
        chars.append(chr(byte_val))
    return ''.join(chars)


def bytes_to_bits(data: bytes) -> list:
    """Chuyển bytes thành list bits"""
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    """Chuyển list bits thành bytes"""
    result = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(bits):
                byte_val = (byte_val << 1) | bits[i + j]
        result.append(byte_val)
    return bytes(result)


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """PKCS#7 padding"""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding"""
    if not data:
        raise ValueError("Invalid padding (empty)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def permute(block: list, table: list) -> list:
    """Hoán vị block theo bảng"""
    return [block[i - 1] for i in table]


def xor_bits(a: list, b: list) -> list:
    """XOR hai list bits"""
    return [x ^ y for x, y in zip(a, b)]


def left_shift(bits: list, n: int) -> list:
    """Dịch trái circular"""
    return bits[n:] + bits[:n]