#!/usr/bin/env python

""" Test a few hash functions to see when they repeat.
"""
from __future__ import print_function
import hashlib


def collition(algorithm, value=chr(0x00).encode()):
    """ Look for a collition.
    """
    idx = 1
    algorithm.update(value)
    seek = algorithm.hexdigest()
    print(seek, idx)
    while True:
        algorithm.update(value)
        hash = algorithm.hexdigest()
        if hash == seek:
            return(idx)
        if idx % 1000000 == 0:
            print(hash, idx)
        idx += 1


if __name__ == '__main__':

    algorithm = hashlib.md5()
    # algorithm = hashlib.sha512()

    print(collition(algorithm))
