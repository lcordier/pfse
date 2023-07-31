#!/usr/bin/env python

"""
    Pretty Frecking Strong Encryption
    (c) 2018-2023 Louis Cordier <lcordier@gmail.com>

    This program focuses on the key distribution problem of one-time pads.
    Instead of distributing a key we distribute a recipe to make a key.
    Thus a size-bounded recipe can be turned into an size-unbounded key.

    Consider using wipe [1] or ya-wipe [2] to securely delete the message
    when you are done encrypting it. See also Peter Gutmann's paper
    "Secure Deletion of Data from Magnetic and Solid-State Memory" [3] for
    reasons why.

    [1] http://lambda-diode.com/software/wipe/ (in most distributions)
    [2] http://wipe.sourceforge.net/ (yet another wipe)
    [3] http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
    [4] https://cryptobook.nakov.com/
"""
import argparse
import csv
import hashlib
import math
import os
import subprocess
import sys

import numpy as np
import requests
import scrypt


SIZE = 4096  # Default file read/write block size, in bytes.
USER_AGENT = 'Mozilla/5.0'

METHODS = [
    'null',
    'md5',
    'scrypt',
    'sha1',
    'sha256',
    'sha512',
]


def pad(key, size=SIZE):
    """ Cyclically pad a key up to a given size.
    """
    if isinstance(key, np.ndarray):
        src = key.tobytes()
    elif isinstance(key, bytes):
        src = key
    elif isinstance(key, str):
        src = bytes(key, 'utf8')
    else:
        raise NotImplementedError(f"Padding not implemented for type: {type(key)}")

    n = len(src)
    b = src * ((size // n) + 1)
    k = np.frombuffer(b, dtype=np.uint8, count=size)
    return k


def gen_password_key(password, size=SIZE):
    """ Generate a key from a password/passphrase.
    """
    return pad(password, size=size)


def gen_file_key(path, size=SIZE):
    """ Read key from a file..
    """
    with open(path, 'rb') as fh:
        blob = fh.read(size)

    return pad(blob, size=size)


def gen_url_key(url, offset=0, size=SIZE):
    """ Obtain a key from an URL.
    """
    headers = {
        'Range': 'bytes={}-{}'.format(offset, offset + size),
        'User-Agent': USER_AGENT,
    }
    response = requests.get(url, headers=headers, stream=True)

    if response.status_code in [200, 206]:
        return pad(response.content, size=size)
    else:
        # 404 + all others.
        raise ValueError("Web Resource Unavailable")


def mutate_hash(key, method='sha256'):
    """ Mutate a key into a new key using a given hash algorithm.
    """
    if method in ['null']:
        return key

    size = len(key)
    src = pad(key, 2 * size).tobytes()

    if method in ['scrypt']:
        hash_ = scrypt.hash

        psize = min(64, size)
        salt = src[:psize]
        n = (size // psize) + 1
        b = bytes()
        i = 0
        while len(b) < size:
            part = src[i * psize:(i + 1) * psize]
            i = (i + 1) % n
            b += hash_(part, salt)

        return np.frombuffer(b, dtype=np.uint8, count=size)

    if method in METHODS:
        hash_ = getattr(hashlib, method)()

        psize = min(len(hash_.digest()), size)
        n = (size // psize) + 1
        b = bytes()
        i = 0
        while len(b) < size:
            part = src[i * psize:(i + 1) * psize]
            i = (i + 1) % n
            hash_.update(part)
            b += hash_.digest()

        return np.frombuffer(b, dtype=np.uint8, count=size)


def mutate_formula(key, formula):
    """ Mutate a key by applying a formula.

        All the functions and constants of the math module are available.
        As well as the following 4 variables/function:

        n = len(key)
        i = 0..n-1
        x = key[i]
        k = lambda i: key[i % n]

        Example formula: 'k(i-1) + k(i+1)'
    """
    size = len(key)
    src = pad(key, size)
    k = [0] * size
    g = math.__dict__.copy()
    g.update({'k': lambda i: int(src[i % size]), 'n': size})
    for i, x in enumerate(src):
        x = int(x)
        g.update({'i': i, 'x': x})
        k[i] = int(eval(formula, g)) % 256

    return np.frombuffer(bytes(k), dtype=np.uint8, count=size) ^ src


def xor(input_, output, key, size=SIZE):
    """ Bitwise XOR input_ with key and write to output.
    """
    key = pad(key, size)
    block = np.frombuffer(input_.read(size), dtype=np.uint8)
    bsize = block.shape[0]

    while bsize > 0:
        # mutate key
        output.write((block ^ key[:bsize]).tobytes())
        block = np.frombuffer(input_.read(size), dtype=np.uint8)
        bsize = block.shape[0]


LOOKUP = {
    'password': gen_password_key,
    'file': gen_file_key,
    'url': gen_url_key,
}

def bake(recipe, secret_ingredient, size=SIZE):
    """ Make a key from a CSV recipe.
    """
    ingredients = []
    with open(recipe, 'r') as fh:
        reader = csv.reader(fh)
        # header = next(reader)
        for row in reader:
            if row:
                type_ = row[0]
                if type_ in ['comment']:
                    continue
                arg = row[1]
                try:
                    ingredients.append(LOOKUP[type_](arg, size=size))
                except Exception as e:
                    print(str(e))
                    sys.exit(1)

    key = ingredients[0]
    for ingredient in ingredients[1:]:
        key = key ^ ingredient

    return mutate_formula(key, secret_ingredient)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', dest='input', action='store', type=str, default='', help='input filename')
    parser.add_argument('-o', '--output', dest='output', action='store', type=str, default='', help='output filename')
    parser.add_argument('-r', '--recipe', dest='recipe', action='store', type=str, default='recipe.csv', help='recipe filename [%(default)s]')
    parser.add_argument('-s', '--secret', dest='secret', action='store', type=str, default='x-y + e**(i % 7)', help='mutation formula, secret ingredient')
    parser.add_argument('-w', '--wipe', dest='wipe', action='store_true', default=False, help='securely wipe the input file')
    args = parser.parse_args()

    input_ = open(args.input, 'rb')
    output = open(args.output, 'wb')
    recipe = args.recipe
    secret = args.secret
    wipe = args.wipe

    if not (input_ and output and secret):
        parser.print_help()
        sys.exit()

    key = bake(recipe, secret)

    # Encrypt key with a master password.
    # with open('key.txt', 'w') as fh:
    #     master_key = mutate_hash(gen_password_key('password;)'), 'scrypt')
    #     fh.write((key ^ master_key).tobytes().hex())

    xor(input_, output, key)

    if wipe:
        command = f'wipe {input_}'
        try:
            subprocess.call(command, shell=True)
        except:
            print('You need to install a secure-wipe utility, either')
            print('http://lambda-diode.com/software/wipe/ or')
            print('http://wipe.sourceforge.net/')
            print('Make sure wipe is in your PATH.')

