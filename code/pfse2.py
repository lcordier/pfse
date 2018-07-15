#!/usr/bin/env python

"""
    https://www.labri.fr/perso/nrougier/teaching/numpy/numpy.html
"""
import hashlib
import math
import matplotlib
matplotlib.use('Agg')
import matplotlib.animation as manimation
import matplotlib.pyplot as plt
import numpy as np


HEX2BIN = {
    '0': '0000',
    '1': '0001',
    '2': '0010',
    '3': '0011',
    '4': '0100',
    '5': '0101',
    '6': '0110',
    '7': '0111',
    '8': '1000',
    '9': '1001',
    'a': '1010',
    'b': '1011',
    'c': '1100',
    'd': '1101',
    'e': '1110',
    'f': '1111',
}

BIN2HEX = {
    '0000': '0',
    '0001': '1',
    '0010': '2',
    '0011': '3',
    '0100': '4',
    '0101': '5',
    '0110': '6',
    '0111': '7',
    '1000': '8',
    '1001': '9',
    '1010': 'a',
    '1011': 'b',
    '1100': 'c',
    '1101': 'd',
    '1110': 'e',
    '1111': 'f',
}

HEX2DEC = {
    '0': 0,
    '1': 1,
    '2': 2,
    '3': 3,
    '4': 4,
    '5': 5,
    '6': 6,
    '7': 7,
    '8': 8,
    '9': 9,
    'a': 10,
    'b': 11,
    'c': 12,
    'd': 13,
    'e': 14,
    'f': 15,
}


def iterate(Z):
    """ Iterate the "Game of Life" Board.

        Copyright INRIA
        Contributors: Nicolas P. Rougier (Nicolas.Rougier@inria.fr)

        DANA is a computing framework for the simulation of distributed,
        asynchronous, numerical and adaptive models.

        This software is governed by the CeCILL license under French law and abiding
        by the rules of distribution of free software. You can use, modify and/ or
        redistribute the software under the terms of the CeCILL license as circulated
        by CEA, CNRS and INRIA at the following URL
        http://www.cecill.info/index.en.html.

        As a counterpart to the access to the source code and rights to copy, modify
        and redistribute granted by the license, users are provided only with a
        limited warranty and the software's author, the holder of the economic
        rights, and the successive licensors have only limited liability.

        In this respect, the user's attention is drawn to the risks associated with
        loading, using, modifying and/or developing or reproducing the software by
        the user in light of its specific status of free software, that may mean that
        it is complicated to manipulate, and that also therefore means that it is
        reserved for developers and experienced professionals having in-depth
        computer knowledge. Users are therefore encouraged to load and test the
        software's suitability as regards their requirements in conditions enabling
        the security of their systems and/or data to be ensured and, more generally,
        to use and operate it in the same conditions as regards security.

        The fact that you are presently reading this means that you have had
        knowledge of the CeCILL license and that you accept its terms.
    """
    # Count neighbours.
    N = (Z[0:-2,0:-2] + Z[0:-2,1:-1] + Z[0:-2,2:] +
         Z[1:-1,0:-2]                + Z[1:-1,2:] +
         Z[2:  ,0:-2] + Z[2:  ,1:-1] + Z[2:  ,2:])

    # Apply rules.
    birth = (N==3) & (Z[1:-1,1:-1]==0)
    survive = ((N==2) | (N==3)) & (Z[1:-1,1:-1]==1)
    Z[...] = 0
    Z[1:-1,1:-1][birth | survive] = 1
    return(Z)


def life_movie(board, steps=100, filename='life.mp4'):
    """ Make a movie about the "Game of Live" evolution of a board.
    """
    FFMpegWriter = manimation.writers['ffmpeg']
    metadata = dict(title='Evolve', artist='Matplotlib', comment='')
    writer = FFMpegWriter(fps=15, metadata=metadata)

    size = np.array(board.shape)
    dpi = 72.0
    figsize = size[1] / float(dpi), size[0] / float(dpi)

    fig = plt.figure(figsize=figsize, dpi=dpi, facecolor="white")
    fig.add_axes([0.0, 0.0, 1.0, 1.0], frameon=False)
    plt.xticks([])
    plt.yticks([])

    with writer.saving(fig, filename, steps):
        for i in range(steps):
            iterate(board)
            plt.imshow(board, interpolation='nearest', cmap=plt.cm.gray_r)
            writer.grab_frame()


def key2board(key):
    """ Turn a key into a "Game of Life" board.

        We might add an arbitrary size parameter.
    """
    Z = np.zeros((512 + 2, ((512 * 4) + 2)), int)
    Z[1:-1, 1:-1] = (np.frombuffer(hex2bin(key), 'u1') - ord('0')).reshape((512, 512 * 4))
    return(Z)


def board2key(Z):
    """ Turn a "Game of Life" board into a key.
    """
    return(bin2hex(array2string(Z[1:-1, 1:-1].reshape((1, 512 * 512 * 4))[0])))


def array2string(arr):
    """ Join the elements in an array into a string.
    """
    size = arr.shape[0]
    return(''.join(str(arr[i]) for i in range(size)))


def bin2hex(binstring):
    """ Converts a binary string into a hex string.
    """
    return(''.join(BIN2HEX[binstring[0+i:4+i]] for i in range(0, len(binstring), 4)))


def hex2bin(hexstring, fill=512):
    """ Convert hex string to a binary string.
    """
    binstring = ''
    for digit in hexstring:
        binstring += HEX2BIN[digit.lower()]

    return(binstring)


def hex2array(hexstring):
    """ Convert a hex string into an array of integers (bytes).
    """
    result = []
    for i in range(0, len(hexstring), 2):
        result.append(HEX2DEC[hexstring[i]] * 16 + HEX2DEC[hexstring[i + 1]])

    return(np.asarray(result))


def split_deck(key, n):
    """ Split the key like a deck of cards.
    """
    size = len(key)
    n = n % size
    return(key[n:] + key[:n])


def split_string(s, size):
    """ Split a string s in sized chunks.
    """
    return([s[0+i:size+i] for i in range(0, len(s), size)])


def generate_passphrase_key(passphrase, hashfunc=hashlib.sha512, size=512*512):
    """ Generate a key of size (in nibbles) by sequentially applying a hash function to the words in a passphrase.
    """
    key = ''
    hash = hashfunc()

    if isinstance(passphrase, str):
        words = passphrase.split()
    elif isinstance(passphrase, (list, tuple)):
        words = passphrase

    n = len(words)

    index = 1
    while len(key) < size:
        hash.update(words[index % n])
        key += hash.hexdigest()
        index += 1

    return(key[:size])


def mutate_key(key, chunk_size, size):
    return(generate_passphrase_key(split_string(key, chunk_size), size=size))






def generate_random_key():
    """
    """

def generate_urandom_key():
    """
    """



k = generate_passphrase_key('0')
Z = key2board(k)
#life_movie(Z)
