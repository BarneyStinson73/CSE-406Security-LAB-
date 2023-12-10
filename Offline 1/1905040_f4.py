import socket
import pickle
import time
# import decrypt
import importlib

decrypt=importlib.import_module("1905040_f1")


# Create a socket
server_socket = socket.socket()
server_address = ('localhost', 12345)
server_socket.bind(server_address)
server_socket.listen(1)

print(f"Server listening on {server_address}")

# Accept a connection from a client
connection, client_address = server_socket.accept()
print(f"Connection from {client_address}")

alice= decrypt.DiffieHellman(128)
alice.generate_key()
# Data to be sent as a tuple
data_to_send = alice.public_key

# Serialize the tuple using pickle and send it to the client
data_to_send_bytes = pickle.dumps(data_to_send)
connection.sendall(data_to_send_bytes)

data_received_bytes = connection.recv(4096)

# Deserialize the received bytes using pickle
data_received = pickle.loads(data_received_bytes)
key=alice.generate_shared_key(data_received)

print(key)

# now send the file with encryption using the shared key

key="".join([chr(byte) for byte in key[0].to_bytes((key[0].bit_length()+7)//8, byteorder='big')])
round_keys_list = decrypt.key_expansion(key)
input_string="Never Gonna Give you up"
# encrypted_mat=convert_to_matrix(input_string)
encrypted_text=decrypt.encryption(input_string,round_keys_list)
print("Encrypted_text")
# print(encryption(encrypted_mat,round_keys_list))
print(encrypted_text)
connection.sendall(encrypted_text.encode('utf-8'))

# Close the connection
connection.close()
server_socket.close()