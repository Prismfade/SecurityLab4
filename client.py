import socket
import hashlib
import os
from hashlib import sha256

from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad

from aes import AES
from key import Key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import rsa
import time
from ca import PK_ca, ID_ca
from datetime import datetime


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        #initialize client identity and keys
        self.id = 'Client'
        self.ip = '127.0.0.1'
        self.PORT = 37128

        #generate RSA key pair
        e_c, d_c, n_c = rsa.generateKey()
        self.public_key = (e_c, n_c)
        self.private_key = (d_c, n_c)

        self.id_ca = ID_ca
        self.ca_public_key = PK_ca

        self.key_helper = Key()

        #establish connection to server
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

    def validate_timestamp(self, timestamp:int, max_time:int = 500):
        now = int(time.time())
        if timestamp > now:
            print("Timestamp is invalid")
            return False
        if now - timestamp > max_time:
            print("Timestamp is invalid")
            return False

        return True

    # for step 3 (print out the plaintext)
    def send_message_for_step3(self):
        TS3 = int(time.time())
        self.TS3 = TS3
        self.server_id = 'ID-Server'
        self.data = 'take cis3319'
        check_time = self.validate_timestamp(self.TS3)

        if not check_time:
            print("Timestamp is invalid")
        else:
            print("Timestamp is valid")

        message_str = f"{self.server_id}|{TS3}"
        message_bytes = message_str.encode()
        print("(client) Step 3: Plaintext message to server:", message_str)

        self.send(message_bytes)

    def receive_server_for_step4(self):
        message_bytes = self.recv()
        message_string = message_bytes.decode()
        print("(client) Step 4: Received encrypted message from server:", message_string)

        try:
            e_s_str, n_s_str, cert_s_str, TS4_str = message_string.split('|')

        except ValueError:
            print("(client) Error: cannot parse server message.")
            return
        
        e_s = int(e_s_str)
        n_s = int(n_s_str)
        cert_s = int(cert_s_str)
        TS4 = int(TS4_str)

        self.server_public_key = (e_s, n_s)
        self.server_cert = cert_s
        self.TS4 = TS4

        check_time = self.validate_timestamp(self.TS4)
        if not check_time:
            print("Timestamp is invalid")
        else:
            print("Timestamp is valid")

        print("(client) Step 4: Parsed PK_s (e,n):", self.server_public_key)
        print("(client) Step 4: Parsed Cert_s:", self.server_cert)
        print("(client) Step 4: Parsed TS4:", self.TS4)

    # client sending RSA_PKs for step 5
    def send_registration_for_step5(self):
        self.ktmp2 = os.urandom(8)
        TS5 = int(time.time())
        self.TS5 = TS5

        try:
            e_s, n_s = self.server_public_key
        except AttributeError:
            print("(client) Error: server public key not in existence.")
            return
        
        ID_c = self.id
        IP_c = self.ip
        Port_c = self.PORT

        plain_string = f"{self.ktmp2.hex()}|{ID_c}|{IP_c}|{Port_c}|{TS5}"
        plain_bytes = plain_string.encode()
        print("(client) Step 5: Plaintext message to server:", plain_string)

        message = int.from_bytes(plain_bytes, byteorder='big')
        c = rsa.encrypt(message, e_s, n_s)
          
        c_string = str(c)
        self.send(c_string.encode())
        print("(client) Step 5: Sent encrypted message to server:", c_string)
##
    #client recieving DES_k for step 6
    def receive_session_key_for_step6(self):
        try:
            Ktmp2 = self.ktmp2
        except AttributeError:
            print("(client) Error: ktmp2 not initalized")
            return
        
        cipher_bytes = self.recv()
        print("(client) step 6: Received encrypted session key from server: ", cipher_bytes.hex())

        des_key = Ktmp2[:8]
        cipher = DES.new(des_key, DES.MODE_ECB)

        decrypted_bytes = cipher.decrypt(cipher_bytes)

        plain_bytes = unpad(decrypted_bytes, 8)
        plain_string = plain_bytes.decode()
        print("(client) step 6: Plaintext message from server:", plain_string)


        try:
            ks_hex, lifetime_session, ID_c_recv, TS6_string = plain_string.split("|")
        except ValueError:
            print("(client) Error: could not parse plaintext")
            return
        
        self.Ks = bytes.fromhex(ks_hex)
        self.lifetime_session = int(lifetime_session)
        self.ID_c_from_serv = ID_c_recv
        self.TS6 = int(TS6_string)

        check_time = self.validate_timestamp(self.TS6)

        if not check_time:
            print("Timestamp is invalid")
        else:
            print("Timestamp is valid")

        print("(client) Step 6: Parse Ks:", self.Ks.hex())
        print("(client) Step 6: Parse Lifetime:", self.lifetime_session)
        print("(client) Step 6: Parse IDc:", self.ID_c_from_serv)
        print("(client) Step 6: Parse TS6:", self.TS6)


    def send_service_request_step7(self):
        TS7 = int(time.time())
        self.TS7 = TS7
        self.req = 'memo'

        try:
            k_sess = self.Ks
        except AttributeError:
            print("(client) Error: k_sess not initalized")
            return


        plain_str = f"{self.req}|{TS7}"
        plain_bytes = plain_str.encode()

        des_key = k_sess[:8]
        cipher = DES.new(des_key, DES.MODE_ECB)
        cipher_bytes = cipher.encrypt(pad(plain_bytes, 8))
        self.send(cipher_bytes)
        print("(client) Step 7: Sent encrypted message to server:", cipher_bytes.hex())

    def receive_service_request_step8(self):
        try:
            k_sess = self.Ks
        except AttributeError:
            print("(client) Step 8: Error: k_sess not initalized")
            return

        cipher_bytes = self.recv()
        print("(client) Step 8: Received encrypted message from Server", cipher_bytes.hex())

        des_key = k_sess[:8]
        cipher = DES.new(des_key, DES.MODE_ECB)

        decrypted_bytes = cipher.decrypt(cipher_bytes)

        plain_bytes = unpad(decrypted_bytes, 8)
        plain_string = plain_bytes.decode()
        print("(client) Step 8: Decrypted plaintext message from server:", plain_string)

        try:
            data,TS8_string = plain_string.split("|")
        except ValueError:
            print("(client) Error: could not parse plaintext")
            return

        self.data = data
        self.TS8 = int(TS8_string)

        check_time = self.validate_timestamp(self.TS8)

        if not check_time:
            print("Timestamp is invalid")
        else:
            print("Timestamp is valid")

        print("(client) Step 8: Parse data:", self.data)
        print("(client) Step 8: Parse TS8:", self.TS8)


if __name__ == '__main__':
    #set up client chat program
    client = Client('127.0.0.1', 37128)
    print("Client information:")
    print("client connected to ID_C: ", client.id)
    print("IP_C", client.ip)
    print("PORT_C", client.PORT)
    print("PK_C", client.public_key)
    print("Trusted CA ID:", client.id_ca)
    print("Trusted CA Public Key:", client.ca_public_key)

    #running step 3
    client.send_message_for_step3()
    #running step 4
    client.receive_server_for_step4()
    #running step 5
    client.send_registration_for_step5()
    #running step 6
    client.receive_session_key_for_step6()
    #running step 7
    client.send_service_request_step7()
    #running step 8
    client.receive_service_request_step8()

    client.close()