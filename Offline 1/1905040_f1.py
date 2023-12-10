# decrypting the encrypted message using AES
import random
import secrets
"""Tables"""

from BitVector import *
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]


def convert_string_to_key0(key):
    array = []
    index = 0
    for i in key:
        array.append(ord(i))

    return array
def circular_left_shift(arr,k):
    arr = arr[k:] + arr[:k]
    return arr
def round_keys_calc(array,iteration):
    index=0
    rc=2**(iteration-1)
    
    w0, w1, w2, w3 = [], [], [], []
    for i in range(0, 4):
        w0.append(array[index])
        index += 1
    for i in range(0, 4):
        w1.append(array[index])
        index += 1
    for i in range(0, 4):
        w2.append(array[index])
        index += 1
    for i in range(0, 4):
        w3.append(array[index])
        index += 1
    
    g3 = circular_left_shift(w3,1)
    
    # byte substitution
    for i in range(0, 4):
        g3[i] = Sbox[g3[i]]
    # xor with rcon
    if rc > 0x80:
        rc= rc ^ (0x11b)
    else:
        rc=rc
    if iteration==10:    
        rc=0x36
    g3[0] = g3[0] ^ rc
    w4 = []
    for i in range(0, 4):
        w4.append(g3[i] ^ w0[i])
    
    w5 = []
    for i in range(0, 4):
        w5.append(w4[i] ^ w1[i])
    
    w6 = []
    for i in range(0, 4):
        w6.append(w5[i] ^ w2[i])
    
    w7 = []
    for i in range(0, 4):
        w7.append(w6[i] ^ w3[i])
    
    return w4,w5,w6,w7
def create_round_key(w4,w5,w6,w7):
    key=[]
    for i in range(0,4):
        key.append(w4[i])
    for i in range(0,4):
        key.append(w5[i])
    for i in range(0,4):
        key.append(w6[i])
    for i in range(0,4):
        key.append(w7[i])
    return key

def transpose_matrix(matrix):
    # Using nested list comprehension to transpose the matrix
    transposed_matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]
    return transposed_matrix

# def sub_bytes(matrix):
#     for i in range(0,4):
#         for j in range(0,4):
#             matrix[i][j]=Sbox[matrix[i][j]]
#     return matrix

def key_expansion(key):
    round_keys_list = []
    round_keys_list.append(convert_string_to_key0(key))
    for i in range(0,10):
        w4, w5, w6, w7 = round_keys_calc(round_keys_list[i],i+1)
        key = create_round_key(w4, w5, w6, w7)
        round_keys_list.append(key)
    return round_keys_list 


def inv_sub_bytes(matrix):
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=InvSbox[matrix[i][j]]
    return matrix
def circular_right_shift(arr, k):
    n = len(arr)
    k = k % n  # Ensure k is within the length of the array

    # Perform the circular right shift
    arr = arr[-k:] + arr[:-k]

    return arr
def decryption(cipher_text,round_keys_list):
    matrix=convert_to_matrix(cipher_text,False)
    backup_matrix=[]
    for i in range (0,len(matrix)):
        backup_matrix.append([])
        for j in range (0,len(matrix[i])):
            backup_matrix[i].append([])
            for k in range (0,len(matrix[i][j])):
                backup_matrix[i][j].append(matrix[i][j][k])
    for k in range(1,len(matrix)):
        matrix[k]=add_round_key(matrix[k],round_keys_list[10])
        # print(matrix[k])
        for i in range(9,0,-1):
            # matrix[k]=inv_shift_rows(matrix[k])
            # print(matrix[k])
            for p in range(0,4):
                matrix[k][p]=circular_right_shift(matrix[k][p],p)
            # print("after shift in iteration ", i)
            # print(matrix[k])
            matrix[k]=inv_sub_bytes(matrix[k])
            # print("after sub in iteration ", i)
            # print(matrix[k])
            matrix[k]=add_round_key(matrix[k],round_keys_list[i])
            # print("after add key in iteration ", i)
            # print(matrix[k])
            matrix[k]=inv_mix_columns(matrix[k])
            # print("after mix col in iteration ", i)
            # print(matrix[k])
        for p in range(0,4):
            matrix[k][p]=circular_right_shift(matrix[k][p],p)
        matrix[k]=inv_sub_bytes(matrix[k])
        matrix[k]=add_round_key(matrix[k],round_keys_list[0])
        matrix[k]=add_iv(matrix[k],backup_matrix[k-1])
    ret = convert_to_string(matrix)
    return ret[16:-ord(ret[len(ret)-1])]

def encryption(plain_text,round_keys_list):
    random_iv = secrets.randbits(128)
    random_iv=[byte for byte in random_iv.to_bytes((random_iv.bit_length() + 7) // 8, byteorder='big')]
    random_iv_string="".join([chr(byte) for byte in random_iv])
    temp_iv=[]
    for i in range(0,4):
        temp_iv.append(random_iv[i*4:i*4+4])
    temp_iv=transpose_matrix(temp_iv)
    matrix=convert_to_matrix(plain_text)
    for k in range(0,len(matrix)):
        matrix[k]=add_iv(matrix[k],temp_iv)
        matrix[k]=add_round_key(matrix[k],round_keys_list[0])
        # printHex(matrix)
        for i in range(1,10):
            # matrix[k]=inv_shift_rows(matrix[k])
            # print("state matrix in iteration ", i)
            # printHex(matrix)
            matrix[k]=sub_bytes(matrix[k])
            # print("after sub in iteration ", i)
            # printHex(matrix)
            for p in range(0,4):
                matrix[k][p]=circular_left_shift(matrix[k][p],p)
            # print("after shift in iteration ", i)
            # printHex(matrix)
            matrix[k]=mix_columns(matrix[k])
            # print("after mix col in iteration ", i)
            # printHex(matrix)
            matrix[k]=add_round_key(matrix[k],round_keys_list[i])
            # print("after add key in iteration ", i)
            # printHex(matrix)
        matrix[k]=sub_bytes(matrix[k])
        for p in range(0,4):
            matrix[k][p]=circular_left_shift(matrix[k][p],p)
        matrix[k]=add_round_key(matrix[k],round_keys_list[10])
        temp_iv=matrix[k]
    return random_iv_string+convert_to_string(matrix)

def mix_columns(matrix):
    new_state_matrix=[]
    for i in range(0,4):
        new_state_matrix.append([])
        for j in range(0,4):
            new_state_matrix[i].append(0)

    AES_modulus = BitVector(bitstring='100011011')
    for i in range(0,4):
        for j in range(0,4):
            for k in range(0,4):
                bv1 = BitVector(intVal=matrix[k][j], size=8)
                bv3 = bv1.gf_multiply_modular(Mixer[i][k], AES_modulus, 8)
                new_state_matrix[i][j]=new_state_matrix[i][j]^bv3.intValue()
    return new_state_matrix

def  sub_bytes(matrix):
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=Sbox[matrix[i][j]]
    return matrix

def shift_rows(matrix):
    for i in range(0,4):
        for j in range(0,i):
            matrix[i]=circular_left_shift(matrix[i])
    return matrix

def inv_mix_columns(matrix):
    new_state_matrix=[]
    for i in range(0,4):
        new_state_matrix.append([])
        for j in range(0,4):
            new_state_matrix[i].append(0)

    AES_modulus = BitVector(bitstring='100011011')
    for i in range(0,4):
        for j in range(0,4):
            for k in range(0,4):
                bv1 = BitVector(intVal=matrix[k][j], size=8)
                bv3 = bv1.gf_multiply_modular(InvMixer[i][k], AES_modulus, 8)
                new_state_matrix[i][j]=new_state_matrix[i][j]^bv3.intValue()
    return new_state_matrix

def add_round_key(matrix,round_key):
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=matrix[i][j]^round_key[j*4+i]
    return matrix

def add_iv(matrix,iv):
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=matrix[i][j]^iv[i][j]
    return matrix

def sub_bytes(matrix):
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=Sbox[matrix[i][j]]
    return matrix

def message_to_matrix(message):
    message_array=[]
    state_matrix=[]
    for i in message:
        message_array.append(ord(i))
    for i in range(0,4):
        state_matrix.append([])
        for j in range(0,4):
            state_matrix[i].append((message_array[i*4+j]))
    print("Initial state Matrix")
    state_matrix=transpose_matrix(state_matrix)
    for i in range(0,4):
        print(state_matrix[i])
    return state_matrix

def convert_to_matrix(input_string,pad=True):
    padding= 16-len(input_string)%16
    if padding == 0:
        padding = 16
    if pad==True:
       input_string += chr(padding) * (padding)

    # Convert the string to a list of lists of integers
    int_list = [[ord(char) for char in input_string[i:i+4]] for i in range(0, len(input_string), 4)]

    # Reshape the list into a 3D list of 4x4 matrices
    three_dimensional_list = [int_list[i:i+4] for i in range(0, len(int_list), 4)]
    for i in range(0,len(three_dimensional_list)):
        three_dimensional_list[i]=transpose_matrix(three_dimensional_list[i])
    return three_dimensional_list

def printHex(encrypted_matrix):
    hex_array = ""
    for k in range(0,len(encrypted_matrix)):
        for i in range(0,4):
            for j in range(0,4):
                hex_array+= hex(encrypted_matrix[k][i][j])+" "
    print(hex_array)

def convert_to_string(encrypted_matrix):
    hex_array = ""
    for k in range(0,len(encrypted_matrix)):
        for i in range(0,4):
            for j in range(0,4):
                hex_array+= chr(encrypted_matrix[k][j][i])
    return hex_array

class DiffieHellman:
    def __init__(self, key):
        if key == 128:
            self.p = 0xfffffffdffffffffffffffffffffffff
            self.a=0xd6031998d1b3bbfebf59cc9bbff9aee1
            self.b= 0x5eeefca380d02919dc2c6558bb6d8a5d
            self.G= (0x7b6aa5d85e572983e6fb32a7cdebc140, 0x27b6916a894d3aee7106fe805fc34b44)
            self.n= 0x3fffffff7fffffffbe0024720613b5a3
            self.h= 0x04
        elif key == 192:
            self.p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
            self.a=0xfffffffffffffffffffffffffffffffefffffffffffffffc
            self.b= 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
            self.G= (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)
            self.n= 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
            self.h= 0x01
        elif key == 256:
            self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
            self.a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
            self.b= 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
            self.G= (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
            self.n= 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
            self.h= 0x01
    
    def point_addition(self, P, Q):
        x1,y1=P
        x2,y2=Q
        if P==Q:
            s = ((3 * x1 * x1 + self.a) * pow(2 * y1,-1,self.p)) % self.p
        elif x1 == x2:
            s=0
        else:
            s = ((y2 - y1) * pow(x2 - x1,-1,self.p))%self.p

        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        return x3, y3
    
    def point_multiplication(self, n, P):
        if n == 0:
            return 0, 0
        if n == 1:
            return P
        if n % 2 == 0:
            new_point= self.point_addition(P, P)
            return self.point_multiplication(n // 2, new_point)
        else:
            new_point= self.point_multiplication(n-1,P)
            return self.point_addition(P, new_point)
        
    def generate_key(self):
        self.private_key = random.randint(1, self.n-1)
        self.public_key =self.point_multiplication(self.private_key, self.G)
        return self.public_key
    
    def generate_shared_key(self, received_public_key):
        return self.point_multiplication(self.private_key, received_public_key)

        
# key="BUET CSE19 Batch"

# round_keys_list = key_expansion(key)

# input_string="Never Gonna Give you up"
# # encrypted_mat=convert_to_matrix(input_string)
# encrypted_text=encryption(input_string,round_keys_list)
# print("encrypted_text")
# # print(encryption(encrypted_mat,round_keys_list))
# print(encrypted_text)


# decrypted_text=decryption(encrypted_text,round_keys_list)
# # print(decrypted_matrix)
# print(decrypted_text)




    
