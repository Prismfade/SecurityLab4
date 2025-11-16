import socket
import hashlib
from aes import AES
from key import Key
from rsa import generateKey
import rsa


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

####
if __name__ == '__main__':
    #establish server connection
    server = Server('0.0.0.0', 37128)
    print(f"Server addr: {server.addr}")

    #generate the aes keys
    e,d,n = generateKey()
    print(f"Public Key (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")

    #variable for public key which makes it easier to send to client
    publicKey = f"{e},{n}".encode('utf-8')
    server.send(publicKey)

    #receive the encrypted aes key
    encryptedBytes = server.recv(4096)

    #to integer
    encryptedInt = int.from_bytes(encryptedBytes, 'big')
    print(f"Encrypted int: {encryptedInt}")

    #decrypt the aes key
    decryptedAes = rsa.decrypt(encryptedInt, d, n)
    print(f"Decrypted AES int: {decryptedAes}")

    #for size
    keyLength = (n.bit_length() + 7) // 8
    #to bytes
    aesKeyBytes = decryptedAes.to_bytes(keyLength, 'big',signed = False)

    #only take last elements if needed
    aesKeyLength = aesKeyBytes[-32:]

    #printing keys
    print(f"Decrypted AES key: {aesKeyLength.hex()}")
    while True:
        aes = AES(aesKeyLength)
        # TODO: your code here
    #message input
        msg = input('> ')
        if msg == 'exit':
            print("Requested to exit. Shutting down server.")
            break

        # TODO: your code here
        #recieve input from client
        data = server.recv(buffer_size=4096)
        encrypted, _, digest = data.rpartition(b'|')
        #if sha digest sent matches calculated digests, then the messages are authenticated
        wantedDigest = hashlib.sha256(encrypted).hexdigest().encode('utf-8')
        print(f"Encrypted message was received: {encrypted.hex()}")
        #digests dont match, do this
        if digest != wantedDigest:
            print("Digest mismatch. Please try again.")
            server.send(b"Message may have been intercepted")

        else:
            #digests match, print that there is a match and proceed with chat
            print("Keys match, Message is verified.")
            decryptedText = aes.decrypt(encrypted)
            server.send(msg.encode('utf-8'))
            print(f"Message was decrypted: {decryptedText}")


    server.close()