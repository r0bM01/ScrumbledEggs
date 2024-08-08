import hashlib, time, secrets, random, base64

class Crypto:
    def __init__(self):
        self.block_size = 2
        self.xor_size = 3
        self.auth_size = 4
        
        self.pad_code = bytes.fromhex("80") * self.xor_size
        
        self.result_data = None
    
    def get_hash(self, data, digest_size = 64, key = b""):
        return hashlib.blake2b(hashlib.blake2b(data).digest(), digest_size = digest_size, key = key).digest()
    
    def get_keyed_password(self, password):
        return self.get_hash(data = password, key = self.get_hash(password))
    
    def bitwise(self, data_a, data_b):
        zero_fill = len(data_a) * 2 
        return bytes.fromhex( hex(int(data_a.hex(), 16) ^ int(data_b.hex(), 16))[2:].zfill(zero_fill) )
    
    def get_padded_data(self, data):
        if len(data) % 2:
            pos = random.randint(0, len(data) - 1)
            data = data[:pos] + self.pad_code + data[pos:]
        return data
    
    def get_depadded_data(self, data):
        if self.pad_code in data:
            pos = data.find(self.pad_code)
            data = data[:pos] + data[pos + len(self.pad_code):]
        return data
    
    def get_bytes_data(self, data):
        if isinstance(data, bytes):
            bytes_data = base64.b64decode(data)
        elif isinstance(data.decode('utf-8'), str):
            bytes_data = bytes.fromhex(data)
        #elif isinstance(data, bytes):
            #bytes_data = data
        return bytes_data
    
    def get_decryption_table(self, keyed_password):
        table = {}
        for i in range(0xffff):
            byte_num = bytes.fromhex(hex(i)[2:].zfill(4))
            hash_value = self.get_hash(data = byte_num, digest_size = self.xor_size, key = keyed_password)
            table[hash_value] = byte_num
        return table
    
    def get_encrypted_data(self, data, password):
        keyed_password = self.get_keyed_password(password)
        padded_data = self.get_padded_data(data)
        
        bytes_group = [padded_data[x:x+self.block_size] for x in range(0, len(padded_data), self.block_size)]
        bytes_hash = [self.get_hash(b, self.xor_size, keyed_password) for b in bytes_group]
        bytes_encrypted = [self.bitwise(b, self.get_hash(keyed_password, self.xor_size)) for b in bytes_hash]
        return b"".join(bytes_encrypted)
    
    def get_decrypted_data(self, data, password):
        keyed_password = self.get_keyed_password(password)
        decryption_table = self.get_decryption_table(keyed_password)
        
        bytes_group = [data[x:x+self.xor_size] for x in range(0, len(data), self.xor_size)]
        bytes_hash = [self.bitwise(b, self.get_hash(keyed_password, self.xor_size)) for b in bytes_group]
        bytes_decrypted = [decryption_table[b] for b in bytes_hash]
        return b"".join(bytes_decrypted)
    
    def digest(self):
        return self.result_data
    
    def hexdigest(self):
        return self.result_data.hex()
    
    def b64digest(self):
        b64 = base64.b64encode(self.result_data)
        return b64.decode('utf-8')
    
    def strdigest(self):
        return self.result_data.decode('utf-8')

    def sign(self, data, password):
        return self.get_hash(data, digest_size = self.auth_size, key = self.get_keyed_password(password))
    
    def verify(self, data, password):
        signature = data[-4:]
        encrypted_data = data[:-4]
        check = self.get_hash(encrypted_data, digest_size = self.auth_size, key = self.get_keyed_password(password))
        if check != signature:
            raise ValueError("Password Error!")
        return encrypted_data
        
    def encrypt(self, message, password, auth = True):
        self.result_data = None
        encrypted_data = self.get_encrypted_data(message.encode('utf-8'), password.encode('utf-8'))
        if auth:
            self.result_data = encrypted_data + self.sign(encrypted_data, password.encode('utf-8'))
        else:
            self.result_data = encrypted_data
        
    def decrypt(self, encrypted_message, password, auth = True):
        self.result_data = None
        data = self.get_bytes_data(encrypted_message.encode('utf-8'))
        data = self.verify(data, password.encode('utf-8'))

        decrypted_data = self.get_decrypted_data(data, password.encode('utf-8'))
        self.result_data = self.get_depadded_data(decrypted_data)
