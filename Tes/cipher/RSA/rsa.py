# cipher/RSA/rsa.py
import random
from typing import Tuple, Optional


class RSACipher:
    # =====================================================
    # BASIC MATH
    # =====================================================
    def gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def egcd(self, a: int, b: int):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = self.egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1

    def mod_inverse(self, e: int, phi: int) -> int:
        g, x, _ = self.egcd(e, phi)
        if g != 1:
            raise ValueError("e và φ(n) không nguyên tố cùng nhau")
        return x % phi

    def is_prime(self, n: int) -> bool:
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        i = 3
        while i * i <= n:
            if n % i == 0:
                return False
            i += 2
        return True

    def generate_prime(self, start=100, end=300) -> int:
        while True:
            n = random.randint(start, end)
            if self.is_prime(n):
                return n

    # =====================================================
    # GENERATE KEYS (FIXED)
    # =====================================================
    def generate_keys(self, p: Optional[int] = None, q: Optional[int] = None):
        # 👉 Nếu không truyền p, q → tự sinh
        if p is None:
            p = self.generate_prime()
        if q is None:
            q = self.generate_prime()

        if p == q:
            raise ValueError("p và q không được bằng nhau")

        if not self.is_prime(p) or not self.is_prime(q):
            raise ValueError("p và q phải là số nguyên tố")

        n = p * q
        phi = (p - 1) * (q - 1)

        # e chuẩn
        e = 65537
        if self.gcd(e, phi) != 1:
            e = 3
            while self.gcd(e, phi) != 1:
                e += 2

        d = self.mod_inverse(e, phi)

        return {
            "p": p,
            "q": q,
            "n": n,
            "phi": phi,
            "public_key": {"e": e, "n": n},
            "private_key": {"d": d, "n": n}
        }

    # =====================================================
    # RSA ENCRYPT / DECRYPT (TEXT)
    # =====================================================
    def encrypt(self, message: str, public_key: Tuple[int, int]) -> str:
        e, n = public_key
        cipher_nums = [pow(ord(ch), e, n) for ch in message]
        return " ".join(map(str, cipher_nums))

    def decrypt(self, cipher_text: str, private_key: Tuple[int, int]) -> str:
        d, n = private_key
        nums = cipher_text.strip().split()
        plain_chars = [chr(pow(int(x), d, n)) for x in nums]
        return "".join(plain_chars)

    # =====================================================
    # SIGN / VERIFY
    # =====================================================
    def sign(self, message: str, private_key: Tuple[int, int]) -> str:
        d, n = private_key
        h = sum(message.encode())
        return str(pow(h, d, n))

    def verify(self, message: str, signature: str, public_key: Tuple[int, int]) -> bool:
        e, n = public_key
        h_real = sum(message.encode())
        h_check = pow(int(signature), e, n)
        return h_real == h_check
