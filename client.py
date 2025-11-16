import socket
import hashlib
from hashlib import sha256
from aes import AES
from key import Key
from rsa import RSA
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
    client = Client('127.0.0.1', 37122)
    

    print("Waiting for public key from server...")

    publicKeyStr = client.recv(1024).decode('utf-8')
    e, n = publicKeyStr.split(',')

    while True:
        #define aes
        aes = AES(key)

        #if user types exit, loop ends
        msg = input('> ')
        if msg == 'exit':
            break

        # TODO: your code here
        #encrypting message using AES and generated key
        encryptedText = AES(key).encrypt(msg)
        print(f"Encrypted message: {encryptedText.hex()}")
        digest = hashlib.sha256(encryptedText).hexdigest()
        print(f"SHA256 Digest of the encrypted text: {digest}")
        pipe = encryptedText + b'|' + bytes(digest, 'utf-8')
        # sends encrypted message to server
        client.send(pipe)
        data = client.recv(1024)
        # gets response from server
        print(f"Server response: {data.decode('utf-8')}")

    client.close()
