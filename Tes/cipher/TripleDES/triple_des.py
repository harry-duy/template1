# cipher/TripleDES/triple_des.py
import os
from cipher.DES.des import (
    generate_subkeys, des_block, bytes_to_bits, 
    bits_to_bytes, xor_bits
)
from cipher.DES.utils import pkcs7_pad, pkcs7_unpad


def parse_key(key_str: str) -> bytes:
    """Parse 3DES key (24 bytes or 48 hex chars)"""
    k = key_str.strip()
    if len(k) == 48 and all(c in "0123456789abcdefABCDEF" for c in k):
        return bytes.fromhex(k)
    else:
        kb = k.encode()
        if len(kb) != 24:
            raise ValueError("3DES key must be 24 bytes or 48 hex chars")
        return kb


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """3DES Encryption (EDE mode with CBC)"""
    if len(key) != 24:
        raise ValueError("3DES key must be 24 bytes")
    
    # Split key into 3 parts
    k1 = key[:8]
    k2 = key[8:16]
    k3 = key[16:24]
    
    # Generate subkeys
    sk1 = generate_subkeys(bytes_to_bits(k1))
    sk2 = generate_subkeys(bytes_to_bits(k2))
    sk3 = generate_subkeys(bytes_to_bits(k3))
    
    # Padding
    plaintext_padded = pkcs7_pad(plaintext, 8)
    
    # Random IV
    iv = os.urandom(8)
    iv_bits = bytes_to_bits(iv)
    
    # CBC mode with 3DES
    prev = iv_bits
    ciphertext_bits = []
    
    for i in range(0, len(plaintext_padded), 8):
        block = plaintext_padded[i:i+8]
        block_bits = bytes_to_bits(block)
        
        # XOR with previous
        xored = xor_bits(block_bits, prev)
        
        # 3DES: Encrypt-Decrypt-Encrypt
        temp1 = des_block(xored, sk1, decrypt=False)
        temp2 = des_block(temp1, sk2, decrypt=True)
        encrypted = des_block(temp2, sk3, decrypt=False)
        
        ciphertext_bits.extend(encrypted)
        prev = encrypted
    
    ciphertext = bits_to_bytes(ciphertext_bits)
    return iv + ciphertext


def decrypt_bytes(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    """3DES Decryption (EDE mode with CBC)"""
    if len(key) != 24:
        raise ValueError("3DES key must be 24 bytes")
    
    if len(iv_and_ciphertext) < 8:
        raise ValueError("Invalid ciphertext")
    
    # Split key into 3 parts
    k1 = key[:8]
    k2 = key[8:16]
    k3 = key[16:24]
    
    # Generate subkeys
    sk1 = generate_subkeys(bytes_to_bits(k1))
    sk2 = generate_subkeys(bytes_to_bits(k2))
    sk3 = generate_subkeys(bytes_to_bits(k3))
    
    # Extract IV
    iv = iv_and_ciphertext[:8]
    ciphertext = iv_and_ciphertext[8:]
    
    if len(ciphertext) % 8 != 0:
        raise ValueError("Invalid ciphertext length")
    
    # CBC mode
    iv_bits = bytes_to_bits(iv)
    prev = iv_bits
    plaintext_bits = []
    
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        block_bits = bytes_to_bits(block)
        
        # 3DES: Decrypt-Encrypt-Decrypt (reverse of EDE)
        temp1 = des_block(block_bits, sk3, decrypt=True)
        temp2 = des_block(temp1, sk2, decrypt=False)
        decrypted = des_block(temp2, sk1, decrypt=True)
        
        # XOR with previous
        plain_block = xor_bits(decrypted, prev)
        plaintext_bits.extend(plain_block)
        
        prev = block_bits
    
    plaintext_padded = bits_to_bytes(plaintext_bits)
    return pkcs7_unpad(plaintext_padded)


class TripleDESCipher:
    def __init__(self):
        pass
    
    def encrypt_bytes_with_key(self, data: bytes, key_str: str) -> bytes:
        key = parse_key(key_str)
        return encrypt_bytes(data, key)
    
    def decrypt_bytes_with_key(self, data: bytes, key_str: str) -> bytes:
        key = parse_key(key_str)
        return decrypt_bytes(data, key)
    
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