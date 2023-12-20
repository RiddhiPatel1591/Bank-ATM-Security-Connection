import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys
import os
import threading

def load_private_key(filename):
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    return private_key

def decrypt_symmetric_key_with_rsa(encrypted_symmetric_key, private_key_path):
    private_key = load_private_key(private_key_path)
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return symmetric_key

def decrypt_text_with_symmetric_key(encrypted_text, symmetric_key):
    cipher = Cipher(algorithms.AES(symmetric_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    # Remove padding
    padding_length = decrypted_text[-1]
    decrypted_text = decrypted_text[:-padding_length]
    return decrypted_text.decode()

def check_credentials(user_id, password):
    with open("password.txt", "r") as file:
        for line in file:
            stored_id, stored_password = line.strip().split()
            if user_id == stored_id and password == stored_password:
                return True
    return False

balance_data_lock = threading.Lock()

def multiple_atm(add,conn):
    try:
        while True:
            encrypted_symmetric_key = conn.recv(4096)
            private_key_path = 'server_private_key.pem'
            symmetric_key = decrypt_symmetric_key_with_rsa(encrypted_symmetric_key, private_key_path)
            encrypted_user_id = conn.recv(4096)
            decrypted_user_id = decrypt_text_with_symmetric_key(encrypted_user_id, symmetric_key)
            encrypted_password = conn.recv(4096)
            decrypted_password = decrypt_text_with_symmetric_key(encrypted_password, symmetric_key)

            if check_credentials(decrypted_user_id, decrypted_password):
                info = "ID and password are correct."
                conn.send(info.encode())

                while True:
                    info = conn.recv(4096).decode("utf-8")
                    info = str(info)
                    if info == "1":
                        user_data = conn.recv(4096).decode("utf-8")
                        recipient_id, amount, account = user_data.strip().split()
                        recipient_id = str(recipient_id)
                        account = str(account)
                        amount = int(amount)
                        count = 0

                        with open("password.txt", 'r') as file:
                            for line in file:
                                row = line.strip().split()
                                if row[0] == recipient_id and recipient_id != decrypted_user_id:
                                    count += 1
                                    recipient_info = "Recepit id present"
                                    conn.send(recipient_info.encode())

                                    with balance_data_lock:
                                        balance_data = {}
                                        with open("balance.txt", "r") as file:
                                            for line in file:
                                                id, savings, checking = line.strip().split()
                                                balance_data[id] = {"savings": int(savings), "checking": int(checking)}

                                        if balance_data[decrypted_user_id][account] >= amount:
                                            info = ">> Your transaction is successful"
                                            conn.send(info.encode())
                                            balance_data[decrypted_user_id][account] -= amount
                                            balance_data[recipient_id][account] += amount

                                            with open("balance.txt", "w") as file:
                                                for id, balances in balance_data.items():
                                                    file.write(f"{id} {balances['savings']} {balances['checking']}\n")
                                        else:
                                            info = ">> Your account has amount less then you entered"
                                            conn.send(info.encode())
                                        break
                        if count == 0:
                            recipient_info = ">> The recipient’s ID error, Please Re-try"
                            conn.send(recipient_info.encode())
                            continue
                    elif info == "2":
                        with open("balance.txt", "r") as file:
                            for line in file:
                                id, saving, checking = line.strip().split()
                                if id == decrypted_user_id:
                                    balance = f"\nYour savings account balance: {saving} Your checking account balance: {checking}"
                                    conn.send(balance.encode())
                    elif info == "3":
                        print(f"Client connection closed: {add}")
                        break
            else:
                info = "ID or password is incorrect. Please try again."
                conn.send(info.encode())
            if info=="3":
                break
    except Exception as e:
        print(f"Error handling client {add}: {e}")
    finally:
        conn.close()

def main():
    if len(sys.argv) != 2:
            print("Enter: python3 bank.py port_number")
            sys.exit(1)
    server_port = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_domain = socket.getfqdn()
    server_socket.bind((server_domain, server_port))
    server_socket.listen(5)
    print("Bank Server is listening...")
    
    while True:
        try:
            conn, add = server_socket.accept()
            print(f"Connection established with {add}")
            client_handler = threading.Thread(target=multiple_atm, args=(add,conn))
            client_handler.start()
        except Exception as e:
            print(f"Error accepting connection: {e}")

if __name__ == "__main__":
    main()
