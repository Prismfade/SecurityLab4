
from rsa import generateKey, decrypt
import hashlib
import time

ID_ca = 'ID-CA'

e_ca, d_ca, n_ca = generateKey()

#public key
PK_ca = (e_ca, n_ca)
#private key
SK_ca = (d_ca, n_ca)

#use key to sign cert
def sign_with_certificate(data: bytes) -> int:
   h = int.from_bytes(hashlib.sha256(data).digest(), byteorder='big')
   sig = pow(h, SK_ca[0], SK_ca[1])
   return sig

def handle_certificate_request(cipher_int: int):
    d_ca, n_ca = SK_ca
    m = decrypt(cipher_int, d_ca, n_ca)
    message_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
    message_str = message_bytes.decode()

    #setup for sending
    Ktmp1_hex, ID_s, TS1_str = message_str.split('|')
    Ktmp1 = bytes.fromhex(Ktmp1_hex)
    TS1 = int(TS1_str)

    print("(CA) Step 2: Received message from Server")
    print("(CA) Parsed values: Ktmp1 (hex):", Ktmp1_hex)
    print("(CA) Parsed values: ID_s:", ID_s)
    print("(CA) Parsed values: TS1:", TS1)

    #generate new keypair
    e_s, d_s, n_s = generateKey()
    PK_s = (e_s, n_s)
    SK_s = (d_s, n_s)

    #building certificate
    cert_toSend = f"{ID_s}|{ID_ca}|{e_s}|{n_s}".encode()
    #hashing
    h_int = int.from_bytes(hashlib.sha256(cert_toSend).digest(), byteorder='big')
    cert_s = pow(h_int, d_ca, n_ca)

    TS2 = int(time.time())

    return PK_s, SK_s, cert_s, TS2, Ktmp1

def get_ca_public_info():
    return {
        "ID_CA": ID_ca,
        "PK_CA": PK_ca,
    }

if __name__ == '__main__':
    print("ID_CA:", ID_ca)
    print("PK_CA:", PK_ca)