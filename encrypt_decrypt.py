from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter


def encrypt_cbc(message, key):
    key = key.decode('hex')
    iv = Random.new().read(AES.block_size)
    a = len(message) % AES.block_size
    padlen = AES.block_size - a
    message += chr(padlen) * padlen
    enc = AES.new(key, AES.MODE_CBC, iv)
    cipher = enc.encrypt(message)
    enc_hex = str(iv + cipher).encode('hex')
    return enc_hex

def decrypt_cbc(cipher, key):
    key = key.decode('hex')
    cipher = cipher.decode('hex')
    iv = cipher[:AES.block_size]
    cipher = cipher[AES.block_size:]
    dec = AES.new(key, AES.MODE_CBC, iv)
    msg = dec.decrypt(cipher)
    padlen = msg[-1]
    pad = ord(padlen)
    msg = msg[:-pad]
    return msg

print decrypt_cbc('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465'
                  'd5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
                  '140b41b22a29beb4061bda66b6747e14')
print decrypt_cbc('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48'
                  'e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253',
                  '140b41b22a29beb4061bda66b6747e14')

def decrypt_ctr(cipher, key):
    cipher = cipher.decode('hex')
    key = key.decode('hex')
    iv = cipher[:AES.block_size]
    cipher = cipher[AES.block_size:]
    ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
    crypto = AES.new(key, AES.MODE_CTR, counter=ctr)
    return crypto.decrypt(cipher)

print decrypt_ctr('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc'
                  '388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
                  '36f18357be4dbd77f050515c73fcf9f2')

print decrypt_ctr('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451',
                  '36f18357be4dbd77f050515c73fcf9f2')

