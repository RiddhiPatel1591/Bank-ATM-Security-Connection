import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import sys
import os

def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def generate_symmetric_key():
    return os.urandom(16)

def encrypt_symmetric_key_with_rsa(symmetric_key, public_key_path):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def encrypt_text_with_symmetric_key(text, symmetric_key):
    block_size = 16
    padding_length = block_size - len(text) % block_size
    padded_text = text.encode() + bytes([padding_length] * padding_length)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return encrypted_text

def main():
    if len(sys.argv) != 3:
        print("run the code as: python3 client.py <server_domain> <server_port>")
        sys.exit(1)
    server_domain = sys.argv[1]
    server_port = int(sys.argv[2])

    # Set up the ATM client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_domain, server_port))

    while True:
        symmetric_key = generate_symmetric_key()
        encrypted_symmetric_key = encrypt_symmetric_key_with_rsa(symmetric_key, 'server_public_key.pem')
        client_socket.sendall(encrypted_symmetric_key)
        user_id = input("Enter your ID: ")
        encrypted_text_user_id = encrypt_text_with_symmetric_key(user_id, symmetric_key)
        client_socket.sendall(encrypted_text_user_id)
        password = input("Enter your password: ")
        encrypted_text_password = encrypt_text_with_symmetric_key(password, symmetric_key)
        client_socket.sendall(encrypted_text_password)

        server_data = client_socket.recv(4096).decode('utf-8')
        print("Received from server:", server_data)
        if server_data=="ID and password are correct.":
            while True:
                info=input("\n**Main Menu \nPlease select one of the following actions :\n1. Transfer money \n2. Check account balance \n3. Exit\nEnter your Response(1, 2 or 3): ")
                if info=="1":
                    client_socket.sendall(info.encode())
                    while True:
                        info1=input("\nSelect account Type :\n1. Savings \n2. Checking\nEnter your Response(1 or 2): ")
                        if info1=="1":
                            recipient_id=input("\nEnter recipient’s ID :")
                            amount=int(input("Enter amount :"))
                            account='savings'
                            user_data = f"{recipient_id} {amount} {account}"
                            client_socket.sendall(user_data.encode())
                            break
                        elif info1=="2":
                            recipient_id=input("\nPlease enter recipient’s ID :")
                            amount=int(input("Please enter amount :"))
                            account='checking'
                            user_data = f"{recipient_id} {amount} {account}"
                            client_socket.sendall(user_data.encode())
                            break
                        else:
                            print("\n>> Please enter 1 for Saving account or 2 for Checking account.")
                            continue
                    recipient_info = client_socket.recv(4096).decode('utf-8')
                    if recipient_info =='>> The recipient’s ID error, Please Re-try':
                        print(recipient_info)
                        continue
                    else:
                        info = client_socket.recv(4096).decode('utf-8')
                        print(info)
                        continue
                elif info=="2":
                    client_socket.sendall(info.encode())
                    balance=client_socket.recv(4096).decode('utf-8')
                    print(balance)
                    continue
                elif info=="3":
                    client_socket.sendall(info.encode())
                    print("\nClosing client connection!")
                    break
                else:
                    print("\n>> Please enter 1, 2 or 3")
                    continue
        elif server_data=="ID or password is incorrect. Please try again.":
            continue
        if info=="3":
            break                      
        else:
            continue

    client_socket.close()

if __name__ == "__main__":
    main()
