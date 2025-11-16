import secrets
import math


def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _modinv(e, phi):
    g, x, _ = _egcd(e, phi)
    if g != 1:
        return None
    return x % phi


def _is_probable_prime(n, k=8):
    if n < 2:
        return False
    # small primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    # write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits=256):
    if bits < 3:
        raise ValueError("bits must be >= 3")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


class RSA:
    """Simple RSA helper. Generates a keypair on construction.

    Methods:
    - public_key -> (e, n)
    - private_key -> (d, n)
    - encrypt_bytes(plaintext_bytes, public_key=None) -> bytes
    - decrypt_bytes(ciphertext_bytes, private_key=None) -> bytes

    NOTE: This is a educational implementation, not suitable for production.
    """

    def __init__(self, bits=256):
        # generate two distinct primes
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits // 2)
        while q == p:
            q = _generate_prime(bits // 2)

        self.n = p * q
        phi = (p - 1) * (q - 1)

        self.e = 65537
        if _egcd(self.e, phi)[0] != 1:
            # fallback to random e
            while True:
                self.e = secrets.randbelow(phi - 3) + 3
                if self.e % 2 == 0:
                    self.e += 1
                if _egcd(self.e, phi)[0] == 1:
                    break

        self.d = _modinv(self.e, phi)
        if self.d is None:
            raise RuntimeError("failed to compute modular inverse")

    @property
    def public_key(self):
        return (self.e, self.n)

    @property
    def private_key(self):
        return (self.d, self.n)

    def encrypt_bytes(self, plaintext: bytes, public_key=None) -> bytes:
        if public_key is None:
            public_key = self.public_key
        e, n = public_key
        m = int.from_bytes(plaintext, 'big')
        if m >= n:
            raise ValueError('plaintext too large for modulus; use larger key size')
        c = pow(m, e, n)
        # serialize ciphertext as fixed-length big-endian bytes (length = modulus length)
        n_bytes = (n.bit_length() + 7) // 8
        return c.to_bytes(n_bytes, 'big')

    def decrypt_bytes(self, ciphertext: bytes, private_key=None) -> bytes:
        if private_key is None:
            private_key = self.private_key
        d, n = private_key
        c = int.from_bytes(ciphertext, 'big')
        m = pow(c, d, n)
        # trim leading zeros
        m_bytes = (m.bit_length() + 7) // 8
        if m_bytes == 0:
            return b""
        return m.to_bytes(m_bytes, 'big')