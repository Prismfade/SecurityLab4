import socket
import hashlib
from hashlib import sha256
from aes import AES
from key import Key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import rsa


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to address: {self.addr}, port: {self.port}")
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes


    def close(self):
        self.s.close()

###
if __name__ == '__main__':
    #set up client chat program
    client = Client('127.0.0.1', 37128)
    aes_key = Key().read('key.bytes')
    print(f"Server on: {client.addr}")

    #client receives the public key from the server
    publicKey = client.recv(buffer_size=4096)
    print(f"Server Public Key: {publicKey}")
    aes = AES(aes_key)
    print(f"AES key: {aes_key.hex()}")


    publicKeyStr = publicKey.decode('utf-8')
    #print(f"Public Key: {publicKeyStr}")
    #splitting e and n values
    eStr, nStr = publicKeyStr.split(',')
    e = int(eStr)
    n = int(nStr)

    #show split of e and n for rsa
    print(f"Public Key: e ={e}, n={n}")

    #encryting the aes key, uses our rsa encrypt program from the rsa.py
    aesKeyInt = int.from_bytes(aes_key, 'big')
    print(f"AES key int: {aesKeyInt}")
    encryptedAes = rsa.encrypt(aesKeyInt, e, n)
    print(f"Encrypted AES key int: {encryptedAes}")

    #establish key length
    keyLength = (n.bit_length() + 7) // 8
    encryptedAesBytes = encryptedAes.to_bytes(keyLength, 'big')

    #print the encrypted key, debugging and testing

    #send encrypted aes key over to server
    client.send(encryptedAesBytes)

    while True:
        #message input by client
        msg = input('> ')
        if msg == 'exit':
            break

        # TODO: your code here
        #use aes to encrypt message
        encryptedMsg = AES(aes_key).encrypt(msg)
        print(f"Encrypted message: {encryptedMsg.hex()}")
        #calculate sha digest for authentication
        digest = hashlib.sha256(encryptedMsg).hexdigest()
        print(f"SHA256 Digest: {digest}")
        #send message with digest to server
        pipe = encryptedMsg + b'|' + bytes(digest, 'utf-8')
        client.send(pipe)
        #print out server message to client
        data = client.recv(buffer_size=4096)
        print(f"Received data: {data.decode('utf-8')}")

    client.close()