import random
from sympy import nextprime
import os

def power (base, exponent, m):
    #this computes the mod m with squaring
    result = 1
    base = base % m
    while exponent > 0:
        # If the exponent is odd
        if (exponent % 2) == 1:
            result = (result * base) % m
        exponent = exponent >> 1
        base = (base * base) % m
    return result

def modInverse(e, m):
    #computing the mod inverse with euclid algorith and phi
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while e > 1:
        q = e // m
        e, m = m, e % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

#generate larger primes that utilize at least 512 bits
def generateLargePrime(bits = 512):
    num = random.getrandbits(bits)
    return nextprime(num)


def generateKey():
    #Generate a both the private and the public keys
    #generate the random primes for p and q
    p = generateLargePrime()
    q = generateLargePrime()

    #get our n value
    n = p * q
    phi = (p - 1) * (q - 1)

    #assign an e value
    e = 65537

    if gcd(e,phi) == 1:
        d = modInverse(e, phi)

    #return our needed variables, e, d and n
        return (e, d, n)


def encrypt(m, e, n):
    #function to encrypt the message
    return pow(m, e, n)

def decrypt(c, d, n):
    #function to encrypt the message
    return pow(c, d, n)

def gcd(a, b):
    #computes our greatest common divisor
    while b != 0:
        a, b = b, a % b
    return a

if __name__== "__main__":
    # Generate Keys
    e, d, n = generateKey()

    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")

    # Message to be encrypted (must be 0 <= message < n)
    message = 100
    print(f"Original Message: {message}")

    # Encrypt the message using the public key (e, n)
    ciphertext = encrypt(message, e, n)
    print(f"Encrypted Message: {ciphertext}")

    # Decrypt the message using the private key (d, n)
    decrypted_message = decrypt(ciphertext, d, n)
    print(f"Decrypted Message: {decrypted_message}")