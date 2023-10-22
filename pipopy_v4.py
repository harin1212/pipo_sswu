#import numpy and struct library
import numpy as np
import struct

#KEYSIZE
SIZE_128 = 16
SIZE_256 = 32

#class PIPO
class PIPO:
    
    @staticmethod
    def int32_to_int8(n):
        mask = (1 << 8) - 1
        return [(n >> k) & mask for k in range(0, 32, 8)]

    # instant variables
    def __init__(self, key, byte_len, iv):

        self.byte_len = byte_len
        self.nblocks = byte_len // 8

        # key_size
        key_size=len(key)
        if key_size == SIZE_128: 
            rounds = 13
            self.key_block = 2
        if key_size == SIZE_256: 
            rounds = 17
            self.key_block = 4
        self.rounds = rounds
        

        #set key
        self.R=np.zeros((int(self.key_block), 8, int(self.nblocks)), dtype=np.uint8)

        #set RoundKey
        for i in range(0, self.key_block):
            for j in range(0, 8):
                self.R[i][j] = np.full((int(self.nblocks)), key[8*i+j], dtype=np.uint8)

  
        #set iv
        self.X = np.zeros((int(self.nblocks), 8), dtype=np.uint8)
        for i in range(0, self.nblocks):
            iv = iv+i
            self.X[i][0:4]=PIPO.int32_to_int8(iv)
            #np.put(self.X, int(i*8),iv+i)
            #self.X[int(i)] = iv + i        

        # transpose
        self.X = np.transpose(self.X)

    # sbox
    def sbox(self, M_not):
        T = np.zeros((3, int(self.nblocks)), dtype=np.uint8)

        # (MSB: x[7], LSB: x[0])
        # Input: x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]
        # S5_1
        self.X[5] ^= (self.X[7] & self.X[6])
        self.X[4] ^= (self.X[3] & self.X[5])
        self.X[7] ^= self.X[4]
        self.X[6] ^= self.X[3]
        self.X[3] ^= (self.X[4] | self.X[5])
        self.X[5] ^= self.X[7]
        self.X[4] ^= (self.X[5] & self.X[6])
        # S3
        self.X[2] ^= self.X[1] & self.X[0]
        self.X[0] ^= self.X[2] | self.X[1]
        self.X[1] ^= self.X[2] | self.X[0]
        self.X[2] = M_not ^ self.X[2]
        # Extend XOR
        self.X[7] ^= self.X[1]
        self.X[3] ^= self.X[2]
        self.X[4] ^= self.X[0]

        # S5_2
        T[0] = self.X[7]
        T[1] = self.X[3]
        T[2] = self.X[4]
        self.X[6] ^= (T[0] & self.X[5])
        T[0] ^= self.X[6]
        self.X[6] ^= (T[2] | T[1])
        T[1] ^= self.X[5]
        self.X[5] ^= (self.X[6] | T[2])
        T[2] ^= (T[1] & T[0])
        # Truncate XOR and bit change
        self.X[2] ^= T[0]
        T[0] = self.X[1] ^ T[2]
        self.X[1] = self.X[0] ^ T[1]
        self.X[0] = self.X[7]
        self.X[7] = T[0]
        T[1] = self.X[3]
        self.X[3] = self.X[6]
        self.X[6] = T[1]
        T[2] = self.X[4]
        self.X[4] = self.X[5]
        self.X[5] = T[2]

    def print_hex(self, text):
        s = ""
        i = 0
        newT = np.array(text, dtype=np.str)
        for i in range(0, len(text), 4):
            a = list(hex(int("".join(newT[i:i+4]))))
            del a[0]
            a.remove('x')
            a = "".join(a)
            s += a
            i += 4

        return '0x'+s
    # Output: (MSb) x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0] (LSb)

    # pbox
    def pbox(self, M):
        # extend number
        self.X[1] = ((self.X[1] & M[1]) << 7) ^ ((self.X[1] & M[8]) >> 1)
        self.X[2] = ((self.X[2] & M[2]) << 4) ^ ((self.X[2] & M[9]) >> 4)
        self.X[3] = ((self.X[3] & M[3]) << 3) ^ ((self.X[3] & M[10]) >> 5)
        self.X[4] = ((self.X[4] & M[4]) << 6) ^ ((self.X[4] & M[11]) >> 2)
        self.X[5] = ((self.X[5] & M[5]) << 5) ^ ((self.X[5] & M[12]) >> 3)
        self.X[6] = ((self.X[6] & M[6]) << 1) ^ ((self.X[6] & M[13]) >> 7)
        self.X[7] = ((self.X[7] & M[7]) << 2) ^ ((self.X[7] & M[14]) >> 6)

    # X : plaintext
    def ENC(self, pt):

        #RCON array
        RCON = np.zeros((int(self.nblocks)), dtype=np.uint8)
        RCON = np.full((int(self.nblocks)), 0x01, dtype=np.uint8)
        RCON_C = np.full((int(self.nblocks)), 0x01, dtype=np.uint8)

        #M array = 16행 nblocks열 / masking
        M = np.zeros((16, int(self.nblocks)), dtype=np.uint8)
        M[1] = np.full((int(self.nblocks)), 0x01, dtype=np.uint8)
        M[2] = np.full((int(self.nblocks)), 0x0f, dtype=np.uint8)
        M[3] = np.full((int(self.nblocks)), 0x1f, dtype=np.uint8)
        M[4] = np.full((int(self.nblocks)), 0x03, dtype=np.uint8)
        M[5] = np.full((int(self.nblocks)), 0x07, dtype=np.uint8)
        M[6] = np.full((int(self.nblocks)), 0x7f, dtype=np.uint8)
        M[7] = np.full((int(self.nblocks)), 0x3f, dtype=np.uint8)

        M[8] = np.full((int(self.nblocks)), 0xfe, dtype=np.uint8)
        M[9] = np.full((int(self.nblocks)), 0xf0, dtype=np.uint8)
        M[10] = np.full((int(self.nblocks)), 0xe0, dtype=np.uint8)
        M[11] = np.full((int(self.nblocks)), 0xfc, dtype=np.uint8)
        M[12] = np.full((int(self.nblocks)), 0xf8, dtype=np.uint8)
        M[13] = np.full((int(self.nblocks)), 0x80, dtype=np.uint8)
        M[14] = np.full((int(self.nblocks)), 0xc0, dtype=np.uint8)

        M_not = np.zeros((int(self.nblocks)), dtype=np.uint8)  # 16행 2열
        M_not = np.full((int(self.nblocks)), 0xff, dtype=np.uint8)

        # key_add
        self.X[0] ^= self.R[0][0]
        self.X[1] ^= self.R[0][1]
        self.X[2] ^= self.R[0][2]
        self.X[3] ^= self.R[0][3]
        self.X[4] ^= self.R[0][4]
        self.X[5] ^= self.R[0][5]
        self.X[6] ^= self.R[0][6]
        self.X[7] ^= self.R[0][7]

        #Round: SIZE_128 = 16 => round=13, SIZE_256 = 32 => round=17
        for i in range(1, int(self.rounds)+1, 1):

            #call sbox
            self.sbox(M_not)

            #call pbox
            self.pbox(M)

            # X XOR RoundKey
            self.X[0] ^= (self.R[i % self.key_block][0] ^ RCON)
            self.X[1] ^= self.R[i % self.key_block][1]
            self.X[2] ^= self.R[i % self.key_block][2]
            self.X[3] ^= self.R[i % self.key_block][3]
            self.X[4] ^= self.R[i % self.key_block][4]
            self.X[5] ^= self.R[i % self.key_block][5]
            self.X[6] ^= self.R[i % self.key_block][6]
            self.X[7] ^= self.R[i % self.key_block][7]

            # RCON plus
            RCON = RCON + RCON_C

        # transpose
        self.X = np.transpose(self.X)

        # CTR (XOR with plaintext)
        CT = np.copy(pt[0:self.nblocks*8])
        start = 0
        for i in range(0, self.nblocks):
            CT[start:start+8]=CT[start:start+8]^self.X[i]
            start = start+8

        return CT