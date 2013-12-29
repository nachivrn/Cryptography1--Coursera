import urllib2

TARGET = 'http://crypto-class.appspot.com/po?er='
CIPHER = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c0' \
         '01bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
BLOCK_SIZE = 16
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------

def query(q):
    target = TARGET + urllib2.quote(q)    # Create query URL
    req = urllib2.Request(target)         # Send HTTP request to server
    try:
        f = urllib2.urlopen(req)          # Wait for response
    except urllib2.HTTPError, e:
        #print "We got: %d" % e.code       # Print response code
        if e.code == 404:
            return True # good padding
        return False # bad padding

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def stror(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) | ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) | ord(y)) for (x, y) in zip(a, b[:len(a)])])

def split_into_blocks():
    blocks = []
    for i in xrange(0, len(CIPHER), 32):
        blocks.append(CIPHER[i:i+32])
    return  blocks

def get_pad_blocks(padval):
    return chr(0) * (BLOCK_SIZE - padval) + chr(padval) * padval

def guesses(padlen, message_block):
    for g in range(2, 255):
        if padlen - 1 == 0:
            guess = message_block[:(BLOCK_SIZE - padlen)] + chr(g)
        else:
            guess = message_block[:(BLOCK_SIZE - padlen)] + chr(g) + message_block[-(padlen-1):]
        yield guess


def guess_block(prev_block, current_block):
    message_block = chr(0) * BLOCK_SIZE
    c0 = prev_block.decode("hex")
    for i in xrange(1, BLOCK_SIZE + 1):
        pad = get_pad_blocks(i)
        for g in guesses(i, message_block):
            prev_block_guess = strxor(strxor(c0,pad), g)
            if query(prev_block_guess.encode('hex')+current_block):
                print "Byte decrypted with guess block: %s and pad block: %s\r" % (g.encode("hex"), pad.encode("hex"))
                message_block = stror(message_block, g)
                break
    return message_block

if __name__ == "__main__":
    cipher_blocks = split_into_blocks()
    message_blocks = ()
    for i in xrange(len(cipher_blocks), 1, -1):
        current_block = cipher_blocks[i - 1]
        prev_block = cipher_blocks[i - 2]
        message_blocks = (guess_block(prev_block, current_block),) + message_blocks
    print "".join(message_blocks)
