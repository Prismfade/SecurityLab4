import socket
import hashlib
from aes import AES
from key import Key
from rsa import RSA
class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()

###
if __name__ == '__main__':
    server = Server('0.0.0.0', 37123)
    
    print("Waiting for key from client...")
    rsa = RSA()
    #Prints public and private key to be sent to client
    print(f"Public Key: {rsa.public_key}"
    print(f"Private Key: {rsa.private_key}")

    #Send key to server
    publicKey = f"{rsa.public_key[0]}|{rsa.public_key[1]}"
    server.send(publicKey.encode('utf-8'))
    print("Public key sent to client.")

    #Recieve encrypted AES
    encryptedAESstr = server.recv(1024).decode('utf-8')
    encrpyptedAESint = int(encryptedAES)
    print(f"Encrypted AES key received: {encrpyptedAESint}")
    
    #Server decrpyt AES using RSA
    decryptedAESKey = rsa.decrypt(encrpyptedAESint, rsa.private_key)
    aesKey = decryptedAESKey.to_bytes((decryptedAESKey.bit_length() + 7) // 8, 'big')
    print(f"Decrypted AES key: {aesKey.hex()}")
    
    while True:
    
        aes = AES(key)

        # TODO: your code here
        print("Server is running...")

        msg = input('> ')
        if msg == 'exit':
            print("Requested to exit. Shutting down server.")
            break

        # TODO: your code here
        #recieve data from client
        data = server.recv(1024)

        #info from client program and decrypting using our common key
        encrypted, _, digest = data.rpartition(b'|')
        wantedDigest = hashlib.sha256(encrypted).hexdigest().encode('utf-8')
        print(f"Encrypted message was received: {encrypted.hex()}")

        #sha digest is returned and checks for key match
        if digest != wantedDigest:
            print("Key does not match.")
            server.send(b"Message may have been intercepted.")

        else:
            # if tags match then print that it does
            print("Keys match, Message is verified.")
            decryptedText = aes.decrypt(encrypted)
            #send decrypted message
            server.send(decryptedText.encode('utf-8'))
            #returning the encrypted message
            print(f"Decrypted text: {decryptedText}")

    server.close()

