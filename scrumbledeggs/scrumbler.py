import hashlib, time, secrets, random, base64

class Crypto:
    def __init__(self):
        self.block_size = 2
        self.hash_chunk = 3
        
        self.pad_code = bytes.fromhex("80") * 3
        
        self.psw_hash = False
        self.xor_chunk = False
        
        self.encryption_lookup = {}
        self.decryption_lookup = {}
        
        self.data = False
    
    def bitwise_op(self, data):
        tmp_data = int(data.hex(), 16)
        xor_op = int(self.xor_chunk.hex(), 16)
        return bytes.fromhex(hex(tmp_data ^ xor_op)[2:].zfill(6))
    
    def sign(self, data, password):
        psw = hashlib.blake2b(password.encode('utf-8'), digest_size = 64).digest()
        signature = hashlib.blake2b(data, digest_size = 4, key = psw).digest()
        return signature
    
    def verify(self, data, password):
        psw = hashlib.blake2b(password.encode('utf-8'), digest_size = 64).digest()
        signature = data[-4:]
        tmp_data = data[:-4]
        if hashlib.blake2b(tmp_data, digest_size = 4, key = psw).digest() == signature:
            return tmp_data
        else:
            assert print("Invalid signature!!")
    
    def set_password(self, password):
        psw = hashlib.blake2b(password.encode('utf-8'), digest_size = 64).digest()
        self.xor_chunk = hashlib.blake2b(psw, digest_size = self.hash_chunk).digest()
        for i in range(65536):
            hex_num = bytes.fromhex(hex(i)[2:].zfill(4))
            hash_value = hashlib.blake2b(hex_num, digest_size = self.hash_chunk, key = psw ).digest()
            self.encryption_lookup[hex_num] = hash_value
            self.decryption_lookup[hash_value] = hex_num
    
    def set_data(self, data):
        tmp_data = data.encode('utf-8')
        if len(tmp_data) % 2:
            pos = random.randint(0, len(tmp_data) - 1)
            tmp_data = tmp_data[:pos] + self.pad_code + tmp_data[pos:]
        data_chunks = [ tmp_data[x:x+2] for x in range(0, len(tmp_data), 2) ]
        hashed_chunks = [ self.encryption_lookup[c] for c in data_chunks ]
        xorred_chunks = [ self.bitwise_op(c) for c in hashed_chunks ]
        data_concat = b"".join(xorred_chunks)
        return data_concat
        
    def encrypt(self, data, password):
        self.set_password(password)
        encrypted_data = self.set_data(data)
        authenticated_data = encrypted_data + self.sign(encrypted_data, password)
        tmp = base64.b64encode(authenticated_data)
        return tmp.decode()
    
    def decrypt(self, data, password):
        self.set_password(password)
        encrypted_data = base64.b64decode(data.encode())
        encrypted_data = self.verify(encrypted_data, password)
        xorred_chunks = [ encrypted_data[c:c+3] for c in range(0, len(encrypted_data), 3) ]
        hashed_chunks = [ self.bitwise_op(c) for c in xorred_chunks ]
        data_chunks = [ self.decryption_lookup[c] for c in hashed_chunks ]
        tmp_data = b"".join(data_chunks)
        if self.pad_code in tmp_data:
            pos = tmp_data.find(self.pad_code)
            tmp_data = tmp_data[:pos] + tmp_data[pos + 3:]
        return tmp_data.decode('utf-8')
