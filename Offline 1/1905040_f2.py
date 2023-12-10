import importlib
import time

decrypt=importlib.import_module("1905040_f1")


key="BUET CSE19 Batch"
print("Key:")
print("In ASCII: ",key)
print("In HEX: ",key.encode('utf-8').hex())
starting_time=time.perf_counter()
round_keys_list = decrypt.key_expansion(key)
ending_time=time.perf_counter()
key_schedule_time=(ending_time-starting_time)*1000

input_string="Never Gonna Give you up"
print("Plain Text: ")
print("In ASCII: ",input_string)
print("In HEX: ",input_string.encode('utf-8').hex())
# encrypted_mat=convert_to_matrix(input_string)
starting_time=time.perf_counter()
encrypted_text=decrypt.encryption(input_string,round_keys_list)
ending_time=time.perf_counter()
encryption_time=(ending_time-starting_time)*1000
print("Ciphered Text: ")
print("In HEX: ",encrypted_text.encode('utf-8').hex())
# print(encryption(encrypted_mat,round_keys_list))
print("In ASCII",encrypted_text)

starting_time=time.perf_counter()
decrypted_text=decrypt.decryption(encrypted_text,round_keys_list)
ending_time=time.perf_counter()
print("Deciphered Text: ")
print("In HEX: ",decrypted_text.encode('utf-8').hex())
print("In ASCII: ",decrypted_text)
decryption_time=(ending_time-starting_time)*1000
print("Execution Time Details: ")
print("Key Schedule Time: ",key_schedule_time,"ms")
print("Encryption Time: ",encryption_time,"ms")
print("Decryption Time: ",decryption_time,"ms")