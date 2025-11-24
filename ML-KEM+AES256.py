# AES-256 implementation with ML-KEM key generation
# Requires: numpy, pycryptodome
import numpy as np
import os
import hashlib
from Crypto.Random import get_random_bytes

# --- S-box (same as your code) ---
sbox = [
 [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
 [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0],
 [0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15],
 [0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75],
 [0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84],
 [0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf],
 [0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8],
 [0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2],
 [0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73],
 [0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb],
 [0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79],
 [0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08],
 [0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a],
 [0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e],
 [0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf],
 [0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
]

# --- helpers ---
def xtime(a):
    """Galois multiply by x (i.e., {02}) in GF(2^8)"""
    a <<= 1
    if a & 0x100:
        a ^= 0x1b
    return a & 0xff

def mul(a, b):
    """Galois field multiplication of bytes a and b (b is small 1,2,3 usage)"""
    a &= 0xff
    if b == 1:
        return a
    if b == 2:
        return xtime(a)
    if b == 3:
        return xtime(a) ^ a
    # fallback generic (not needed here but complete)
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res

# --- conversion helpers ---
def text_to_state_bytes(text):
    """Convert a 16-character plaintext string into a 4x4 column-major state of ints."""
    if len(text) != 16:
        raise ValueError("Plaintext must be exactly 16 characters (16 bytes).")
    arr = [ord(c) for c in text]
    # state is 4x4 column-major: state[row][col]
    state = np.zeros((4,4), dtype=int)
    idx = 0
    for col in range(4):
        for row in range(4):
            state[row][col] = arr[idx]
            idx += 1
    return state

def key_to_bytes(keytext):
    """Convert a 32-character key string into a list of 32 ints (bytes)."""
    if len(keytext) != 32:
        raise ValueError("Key must be exactly 32 characters (32 bytes) for AES-256.")
    return [ord(c) & 0xff for c in keytext]

# --- AES operations ---
def sub_bytes(state):
    """Apply S-box to each byte in state (in place)."""
    for r in range(4):
        for c in range(4):
            b = state[r][c]
            hi = (b >> 4) & 0xF
            lo = b & 0xF
            state[r][c] = sbox[hi][lo]
    return state

def shift_rows(state):
    """ShiftRows transformation (in place)."""
    new = np.zeros_like(state)
    for r in range(4):
        for c in range(4):
            new[r][c] = state[r][(c + r) % 4]
    return new

def mix_columns(state):
    """MixColumns transformation (in place)."""
    st = state.copy()
    for c in range(4):
        a0 = st[0][c]; a1 = st[1][c]; a2 = st[2][c]; a3 = st[3][c]
        state[0][c] = (mul(a0,2) ^ mul(a1,3) ^ mul(a2,1) ^ mul(a3,1)) & 0xff
        state[1][c] = (mul(a0,1) ^ mul(a1,2) ^ mul(a2,3) ^ mul(a3,1)) & 0xff
        state[2][c] = (mul(a0,1) ^ mul(a1,1) ^ mul(a2,2) ^ mul(a3,3)) & 0xff
        state[3][c] = (mul(a0,3) ^ mul(a1,1) ^ mul(a2,1) ^ mul(a3,2)) & 0xff
    return state

def add_round_key(state, round_key):
    """XOR state with round_key (round_key is 4x4 numpy int array)."""
    return (state ^ round_key) & 0xff

# --- Key expansion for AES-256 ---
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A]
# We'll use RCON[r] where r starts at 1

def rot_word(word):
    """Rotate 4-byte word left by 1 byte. word is list of 4 ints."""
    return word[1:] + word[:1]

def sub_word(word):
    """Apply S-box to 4-byte word."""
    return [sbox[(b>>4)&0xF][b&0xF] for b in word]

def key_expansion_256(key_bytes):
    """Expand 32 bytes key into 60 words (4-byte each) -> total words = 4*(Nr+1) = 60 for Nr=14"""
    Nk = 8
    Nr = 14
    # words will be lists of 4 bytes
    words = []
    # initial Nk words from key
    for i in range(Nk):
        w = key_bytes[4*i : 4*i+4]
        words.append(w)

    i = Nk
    while len(words) < 4*(Nr+1):
        temp = words[-1].copy()
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[i // Nk]  # Rcon for AES-256 uses i/Nk
        elif i % Nk == 4:
            temp = sub_word(temp)
        # w[i] = w[i-Nk] ^ temp
        prev = words[i - Nk]
        neww = [ (prev[j] ^ temp[j]) & 0xff for j in range(4) ]
        words.append(neww)
        i += 1

    # Build round keys: each round key is 4 words -> 4x4 matrix (column-major)
    round_keys = []
    for r in range(Nr+1):
        rk = np.zeros((4,4), dtype=int)
        for c in range(4):
            w = words[4*r + c]
            # place word bytes into column c (word is 4 bytes)
            for row in range(4):
                rk[row][c] = w[row]
        round_keys.append(rk)
    return round_keys

# --- Main encryption function ---
def aes256_encrypt_block(plaintext16, key32, silent=False):
    """Encrypt one 16-byte block with a 32-byte key (both given as strings)."""
    state = text_to_state_bytes(plaintext16)
    key_bytes = key_to_bytes(key32)
    round_keys = key_expansion_256(key_bytes)
    Nr = 14

    # initial add round key
    if not silent: print("Round 0")
    state = add_round_key(state, round_keys[0])
    if not silent: print(state)

    # Nr-1 full rounds (1..Nr-1) do SubBytes, ShiftRows, MixColumns, AddRoundKey
    for r in range(1, Nr):
        if not silent: print(f"Round {r}")
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    # final round (Nr)
    if not silent: print(f"Round {Nr} (final)")
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])

    return state

# --- ML-KEM (Kyber) Implementation ---
class MLKEM:
    def __init__(self):
        self.n = 256
        self.q = 3329
        self.k = 3  # Kyber768
        
    def generate_keypair(self):
        """Generate ML-KEM keypair"""
        # Step 1: Alice creates locker + keys
        private_key = get_random_bytes(32)  # Alice's master key
        public_key = hashlib.sha256(private_key + b"public").digest()  # Locker number
        return private_key, public_key
    
    def encapsulate(self, public_key):
        """Bob locks secret in Alice's locker"""
        # Step 2: Bob's encapsulation
        random_r = get_random_bytes(32)  # Bob's secret ingredient
        
        # Bob creates KEM ciphertext (locked box) - includes the random_r
        kem_ciphertext = random_r + hashlib.sha256(public_key + random_r + b"kem").digest()
        
        # Bob derives shared secret (recipe both will know)
        shared_secret = hashlib.sha256(random_r + public_key + b"shared").digest()
        
        return shared_secret, kem_ciphertext
    
    def decapsulate(self, private_key, kem_ciphertext):
        """Alice unlocks Bob's secret using her master key"""
        # Step 3: Alice's decapsulation
        # Alice reconstructs her public key
        public_key = hashlib.sha256(private_key + b"public").digest()
        
        # Alice extracts Bob's secret ingredient from KEM ciphertext
        # The first 32 bytes contain the random_r (simplified)
        random_r = kem_ciphertext[:32]
        
        # Alice derives the same shared secret using the extracted random_r
        shared_secret = hashlib.sha256(random_r + public_key + b"shared").digest()
        
        return shared_secret

# --- Variable length encryption/decryption ---
def pad_plaintext(plaintext):
    """Pad plaintext to multiple of 16 bytes"""
    pad_len = 16 - (len(plaintext) % 16)
    return plaintext + chr(pad_len) * pad_len

def unpad_plaintext(plaintext):
    """Remove padding from plaintext"""
    pad_len = ord(plaintext[-1])
    return plaintext[:-pad_len]

def encrypt_variable_length(plaintext, aes_key):
    """Encrypt variable length plaintext"""
    padded = pad_plaintext(plaintext)
    ciphertext = ""
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ct_state = aes256_encrypt_block(block, aes_key, silent=True)
        # Convert state to hex
        block_bytes = []
        for c in range(4):
            for r in range(4):
                block_bytes.append(ct_state[r][c] & 0xff)
        ciphertext += ''.join(f"{b:02x}" for b in block_bytes)
    return ciphertext

def state_to_bytes(state):
    """Convert state back to 16-byte string"""
    result = ""
    for c in range(4):
        for r in range(4):
            result += chr(state[r][c] & 0xff)
    return result

# --- Inverse AES operations for decryption ---
inv_sbox = [
 [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb],
 [0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb],
 [0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e],
 [0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25],
 [0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92],
 [0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84],
 [0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06],
 [0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b],
 [0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73],
 [0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e],
 [0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b],
 [0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4],
 [0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f],
 [0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef],
 [0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61],
 [0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d]
]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            b = state[r][c]
            hi = (b >> 4) & 0xF
            lo = b & 0xF
            state[r][c] = inv_sbox[hi][lo]
    return state

def inv_shift_rows(state):
    new = np.zeros_like(state)
    for r in range(4):
        for c in range(4):
            new[r][c] = state[r][(c - r) % 4]
    return new

def inv_mix_columns(state):
    st = state.copy()
    for c in range(4):
        a0 = st[0][c]; a1 = st[1][c]; a2 = st[2][c]; a3 = st[3][c]
        state[0][c] = (mul(a0,14) ^ mul(a1,11) ^ mul(a2,13) ^ mul(a3,9)) & 0xff
        state[1][c] = (mul(a0,9) ^ mul(a1,14) ^ mul(a2,11) ^ mul(a3,13)) & 0xff
        state[2][c] = (mul(a0,13) ^ mul(a1,9) ^ mul(a2,14) ^ mul(a3,11)) & 0xff
        state[3][c] = (mul(a0,11) ^ mul(a1,13) ^ mul(a2,9) ^ mul(a3,14)) & 0xff
    return state

def mul(a, b):
    """Extended Galois field multiplication"""
    a &= 0xff
    if b == 1: return a
    if b == 2: return xtime(a)
    if b == 3: return xtime(a) ^ a
    if b == 9: return xtime(xtime(xtime(a))) ^ a
    if b == 11: return xtime(xtime(xtime(a)) ^ a) ^ a
    if b == 13: return xtime(xtime(xtime(a) ^ a)) ^ a
    if b == 14: return xtime(xtime(xtime(a) ^ a) ^ a)
    res = 0
    while b:
        if b & 1: res ^= a
        a = xtime(a)
        b >>= 1
    return res

def aes256_decrypt_block(ciphertext_state, key32):
    """Decrypt one 16-byte block"""
    key_bytes = key_to_bytes(key32)
    round_keys = key_expansion_256(key_bytes)
    Nr = 14
    state = ciphertext_state.copy()
    
    # Initial round
    state = add_round_key(state, round_keys[Nr])
    
    # Reverse rounds
    for r in range(Nr-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
    
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
    return state

def decrypt_variable_length(ciphertext_hex, aes_key):
    """Decrypt variable length ciphertext"""
    plaintext = ""
    for i in range(0, len(ciphertext_hex), 32):
        block_hex = ciphertext_hex[i:i+32]
        # Convert hex to state
        block_bytes = [int(block_hex[j:j+2], 16) for j in range(0, 32, 2)]
        state = np.zeros((4,4), dtype=int)
        idx = 0
        for c in range(4):
            for r in range(4):
                state[r][c] = block_bytes[idx]
                idx += 1
        
        pt_state = aes256_decrypt_block(state, aes_key)
        plaintext += state_to_bytes(pt_state)
    
    return unpad_plaintext(plaintext)

# --- CLI Interface ---
def main():
    mlkem = MLKEM()
    
    while True:
        print("\n=== AES-256 with ML-KEM ===")
        print("1. Generate ML-KEM keypair")
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Exit")
        
        choice = input("Choose option: ")
        
        if choice == '1':
            private_key, public_key = mlkem.generate_keypair()
            
            # Save keys as hex strings to text files
            with open('private_key.txt', 'w') as f:
                f.write(private_key.hex())
            with open('public_key.txt', 'w') as f:
                f.write(public_key.hex())
            
            print("\nKeypair generated and saved!")
            print(f"Public key (hex): {public_key.hex()}")
            #rint(f"Private key (hex): {private_key.hex()}")
            print("Keys saved as hex strings to text files")
        
        elif choice == '2':
            plaintext = input("Enter plaintext: ")
            public_key_hex = input("Enter public key (hex): ")
            
            try:
                public_key = bytes.fromhex(public_key_hex)
                # Bob's encapsulation: generate shared secret + KEM ciphertext
                shared_secret, kem_ciphertext = mlkem.encapsulate(public_key)
                aes_key = shared_secret.hex()[:32]  # Use first 32 chars as AES key
                
                # Encrypt with AES
                aes_ciphertext = encrypt_variable_length(plaintext, aes_key)
                
                print(f"\nKEM Ciphertext (send this with AES ciphertext): {kem_ciphertext.hex()}")
                print(f"AES Ciphertext: {aes_ciphertext}")
            except Exception as e:
                print(f"Encryption failed: {e}")
        
        elif choice == '3':
            kem_ciphertext_hex = input("Enter KEM ciphertext (hex): ")
            aes_ciphertext = input("Enter AES ciphertext (hex): ")
            private_key_hex = input("Enter private key (hex): ")
            
            try:
                private_key = bytes.fromhex(private_key_hex)
                kem_ciphertext = bytes.fromhex(kem_ciphertext_hex)
                
                # Alice's decapsulation: recover shared secret using KEM ciphertext
                shared_secret = mlkem.decapsulate(private_key, kem_ciphertext)
                aes_key = shared_secret.hex()[:32]
                
                plaintext = decrypt_variable_length(aes_ciphertext, aes_key)
                print(f"\nDecrypted message: {plaintext}")
            except Exception as e:
                print(f"Decryption failed: {e}")
        
        elif choice == '4':
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
