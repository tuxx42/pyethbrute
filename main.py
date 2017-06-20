#!/usr/bin/env python

import json
import time
import hashlib
from datetime import timedelta
from itertools import islice
from multiprocessing import Pool
from bitcoin import encode_pubkey, privtopub
from python_sha3 import sha3_256, encode_hex
from Crypto.Cipher import AES


iv = None
cipher = None
ethaddr = None


# XXX replace this with openssl
def pbkdf2(iv, cipher, password):
    pw = password.strip()
    return hashlib.pbkdf2_hmac('sha256', pw, pw, 2000)[:16]


def wallet_info():
    with open('ethwallet.json', 'r') as f:
        m = json.loads(f.read())
        data = bytes.fromhex(m['encseed'])
        iv = data[:16]
        cipher = data[16:-16]
        ethaddr = m['ethaddr']
    return iv, cipher, ethaddr


def secure_privtopub(priv):
    if len(priv) == 64:
        return secure_privtopub(priv.decode('hex')).encode('hex')
    return privtopub(priv)


def eth_privtoaddr(priv):
    pub = encode_pubkey(secure_privtopub(priv), 'bin_electrum')
    return encode_hex(sha3_256(pub).digest()[12:])


def crunch_seed(iv, cipher, ethaddr, key, pw):
    try:
        aes_object = AES.new(key, AES.MODE_CBC, iv)
        seed = aes_object.decrypt(cipher)
    except Exception as e:
        raise "AES Decryption error. Bad password?"
    try:
        # XXX cant use:
        # Ethereum uses KECCAK-256. It should be noted that it
        # does not follow the FIPS-202 based standard (aka SHA-3),
        # which was finalized in August 2015.
        ethpriv = sha3_256(seed).digest()
        eth_privtoaddr(ethpriv)
    except Exception as e:
        raise e
    if eth_privtoaddr(ethpriv) == ethaddr:
        raise Exception("FOUND PASSWORD", pw)


def crunch_passwords(password):
    global iv, cipher, ethaddr

    password = password.strip()
    key = pbkdf2(iv, cipher, password)
    crunch_seed(iv, cipher, ethaddr, key, password)


def readlines(n, skip=0):
    with open('password.list', 'rb') as f:
        for _ in range(skip):
            next(f)
        while True:
            next_n_lines = list(islice(f, n))
            if not next_n_lines:
                break
            yield next_n_lines


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def __main__():
    global iv, cipher, ethaddr
    iv, cipher, ethaddr = wallet_info()

    number_of_procs = 200

    skip_lines = 0
    number_of_lines = file_len('password.list')

    pool = Pool(number_of_procs)
    run = time.time()
    start = time.time()
    i = skip_lines
    for passwords in readlines(number_of_procs, skip_lines):
        i += number_of_procs
        pool.map(crunch_passwords, passwords)
        if i % (100 * number_of_procs) == 0:
            end = time.time()
            pps = (100 * number_of_procs) / (end - start)
            print("{:>17}/{} ({:6.2f} %) ({:<20.2f} p/s) ({}) ({})".format(
                i, number_of_lines, float(i / number_of_lines) * 100,
                pps, str(timedelta(seconds=end - run)), passwords[0])
            )
            start = time.time()


if __name__ == '__main__':
    __main__()
