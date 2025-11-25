import socket
import hashlib
import os
from aes import AES
from key import Key
from rsa import generateKey
import time
import rsa
from ca import PK_ca, ID_ca, handle_certificate_request

class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()
        
        #initialize server identity and keys
        self.ID_s = 'ID-Server'
        self.key_helper = Key()

        #ca info
        self.ca_id = ID_ca
        self.call_public_key = PK_ca


        #placeholder for RSA key and cert
        self.public_key = None
        self.private_key = None
        self.cert_server = None

    
    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()


    def register_with_certificate_for_step1(self):
        self.Ks_tmp = os.urandom(8)
        #created timestamp 1
        TS1 = int(time.time())
        print("(server) For step 1: create temporary Ks_tmp key")
        print("(server) Generated Ks_tmp in hex: ", self.Ks_tmp.hex())

        message_plain = f"{self.Ks_tmp.hex()}|{self.ID_s}|{TS1}".encode()
        print("(server) Plain message to CA: ", message_plain.decode())

        m = int.from_bytes(message_plain, byteorder='big')

        #RSA encrypt with CA public key
        e_ca, n_ca = self.call_public_key
        c = rsa.encrypt(m, e_ca, n_ca)
        print("(server) Step 1: Sent encrypted ciphertext to CA", hex(c)[2:])

        PK_s, SK_s, Cert_s, TS2, KS_tmp_back = handle_certificate_request(c)

        if KS_tmp_back == self.Ks_tmp:
            print("(server) Cert registration is matched and verified")
        else:
            print("(server) Mismatch, registration failed")

        self.public_key = PK_s
        self.private_key = SK_s
        self.cert_server = Cert_s

        print("(server) Step 2: registration completed with CA")
        print("(server) Server Public Key:", self.public_key)
        print("(server) Server Private Key:", self.private_key)
        print("(server) Server Certificate:", self.cert_server)
        
    #for step 3 and 4 where server gets message from client then prints the values
    def recieve_message_for_step3and4(self):
        msg_bytes = self.recv()
        msg_str = msg_bytes.decode()
        print("(server) Step 3: Received plain message from client:", msg_str)

        try:
            ID_s_recv, TS3_str = msg_str.split('|')
        except:
            print("(server) cannot parse message")
            return
        
        self.TS3 = int(TS3_str)

        print("(server) Parsed values:", ID_s_recv)
        print("(server) Parsed timestamp TS3:", self.TS3)

        if ID_s_recv != self.ID_s:
            print("(server) Warning: ID_s does not match server ID")

    #step 4 for sending out
    def send_certification_for_step4(self):
        # a check for checking if public key or certification from the server is initalized, had to find on internet
        if self.public_key is None or self.cert_server is None:
            print("(server) Error: server keys or certificate not initialized")
            return
        
        e_s, n_s = self.public_key
        cert_s = self.cert_server
        TS4 = int(time.time())
        self.TS4 = TS4

        
        #build message
        message = f"{e_s}|{n_s}|{cert_s}|{TS4}".encode()

        print("(server) Step 4: Sent the ID, PK_s, Cert_s, and randomValue to cleint")
        print("(server) Message: ", message)
        
        #send value to client
        self.send(message)

    #step 5 for receiving registration from client
    def recieve_registration_for_step5(self):
        message_bytes = self.recv()
        message_string = message_bytes.decode()
        print("(server) Step 5: Received encrypted message from client:", message_string)

        try:
            c = int(message_string)
        except ValueError:
            print("(server) Error: cannot parse client message.")
            return
        
        if self.private_key is None:
            print("(server) Error: server private key not initialized")
            return
        
        d_s, n_s = self.private_key
        message = rsa.decrypt(c, d_s, n_s)

        plain_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
        plain_string = plain_bytes.decode()
        print("(server) Step 5: Decrypted message from client:", plain_string)

        try:
            Ktmp2_hex, ID_c, IP_c, Port_c, TS5_str = plain_string.split('|')
        except ValueError:
            print("(server) Error: cannot parse decrypted client message.")
            return
        
        self.Ktmp2 = bytes.fromhex(Ktmp2_hex)
        self.ID_c = ID_c
        self.IP_c = IP_c
        self.Port_c = Port_c
        TS5 = int(TS5_str)

        print("(server) Step 5: Parsed Ktmp2 (hex):", Ktmp2_hex)
        print("(server) Step 5: Parsed ID_c:", ID_c)
        print("(server) Step 5: Parsed IP_c:", IP_c)
        print("(server) Step 5: Parsed Port_c:", Port_c)
        print("(server) Step 5: Parsed TS5:", TS5)
    
    #step 6 for sending out DES_k to client
    def send_session_key_step6(self):
        try:
            ktmp2 = self.Ktmp2
        except AttributeError:
            print("(server) Error: ktmp2 is not initalized")
            return
        
        #setup ks_hex
        self.Ks = os.urandom(8)
        ks_hex = self.Ks.hex

        lifetime_session = 120
        TS6 = int(time.time())
        self.TS6 = TS6

        try:
            ID_c = self.ID_c
        except:
            ID_c = "ID-Client"

        plain_str = f"{ks_hex}|{lifetime_session}|{ID_c}|{TS6}"

        plain_bytes = plain_str.encode()
        print("(server) Step6: Plaintext before AES(ktmp2):", plain_str)

        aes = AES(ktmp2)
        cipher_bytes = aes.encrypt(plain_bytes)

        self.send(cipher_bytes)
        print("(server) Step 6: Send encrpyted session key to client.")


if __name__ == '__main__':
    #establish server connection
    server = Server('0.0.0.0', 37128)
    print(f"Server addr: {server.addr}")

    server.register_with_certificate_for_step1()
    server.recieve_message_for_step3and4()
    server.send_certification_for_step4()
    server.recieve_registration_for_step5()
    # server.send_session_key_step6()
    server.close()