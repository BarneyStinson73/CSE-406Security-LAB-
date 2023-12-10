import importlib
import time

decrypt=importlib.import_module("1905040_f1")

for i in [128,192,256]:
    A_time=0
    B_time=0
    shared_key_time=0
    for k in range(0,5):
        alice= decrypt.DiffieHellman(i)
        start_time=time.perf_counter()
        alice.generate_key()
        end_time=time.perf_counter()
        A_time+=(end_time-start_time)*1000
        Bob= decrypt.DiffieHellman(i)
        start_time=time.perf_counter()
        Bob.generate_key()
        end_time=time.perf_counter()
        B_time+=(end_time-start_time)*1000
        start_time=time.perf_counter()
        alice.generate_shared_key(Bob.public_key)
        end_time=time.perf_counter()
        shared_key_time+=(end_time-start_time)*1000
        # Bob.generate_shared_key(alice.public_key)
    print("For ",i," bit key: ")
    print("Alice's Key Generation Time: ",A_time/5,"ms")
    print("Bob's Key Generation Time: ",B_time/5,"ms")
    print("Shared Key Generation Time: ",shared_key_time/5,"ms")