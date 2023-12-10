import socket
import pickle
import time
import importlib

decrypt=importlib.import_module("1905040_f1")

# Create a socket
client_socket = socket.socket()
server_address = ('localhost', 12345)

# Connect to the server
client_socket.connect(server_address)

# Receive the serialized tuple from the server
data_received_bytes = client_socket.recv(4096)

# Deserialize the received bytes using pickle
data_received = pickle.loads(data_received_bytes)

# Print the received tuple
print("Received data:", data_received)

Bob= decrypt.DiffieHellman(128)
Bob.generate_key()
client_socket.sendall(pickle.dumps(Bob.public_key))


key=Bob.generate_shared_key(data_received)
key="".join([chr(byte) for byte in key[0].to_bytes((key[0].bit_length()+7)//8, byteorder='big')])
round_keys_list = decrypt.key_expansion(key)
encrypted_text=client_socket.recv(4096).decode('utf-8')
decrypted_text=decrypt.decryption(encrypted_text,round_keys_list)
# print(decrypted_matrix)
print(decrypted_text)
client_socket.close()
