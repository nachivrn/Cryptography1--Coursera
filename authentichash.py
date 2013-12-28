from Crypto.Hash import SHA256
import sys

def compute_hash(chunks):
    sha256 = SHA256.new()
    sha256.update(chunks)
    return sha256.digest()

def get_chunks(bytes, chunksize=1024):
    if bytes:
        file_size = len(bytes)
        chunk_ctr = file_size/chunksize
        last_chunks = bytes[chunk_ctr*chunksize:]
        while chunk_ctr >= 0:
            if last_chunks:
                chunks = last_chunks
                last_chunks = None
            else:
                chunks = bytes[chunk_ctr*chunksize:chunk_ctr*chunksize+1024]
            chunk_ctr = chunk_ctr - 1
            yield chunks 
            

def main(argv):
    hash =''
    with open(argv[0], "rb") as f:
        bytes = f.read()
    for chunk in get_chunks(bytes):
        chunk = chunk + hash
        hash = compute_hash(chunk)
    print hash.encode('hex')


if __name__ == '__main__':
    main(sys.argv[1:])
