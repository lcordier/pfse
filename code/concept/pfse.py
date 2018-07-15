#!/usr/bin/env python

"""
    Pretty Frecking Strong Encryption
    
    Author: Louis Cordier <lcordier@gmail.com>
    Copyright: (c) 2009, All rights reserved.
    Last Modified: 2009-09-06
    
    This program focuses on the key distribution problem of one-time pads. 
    Instead of distributing a key we distribute a recipe to make a key. 
    Thus a size-bounded recipe can be turned into an size-unbounded key.
    For example a 5 characters recipe can be turned into a 1TB key.
    Given a (publicly shared) recipe and a small shared secret (ingredient)
    the generated key can be concidered random for all practical purposes.
    
    Consider using wipe [1] or ya-wipe [2] to securely delete files, the
    message for example when you are done encrypting it. 
    See also Peter Gutmann's paper "Secure Deletion of Data from Magnetic
    and Solid-State Memory" [3] for reasons why.
    
    [1] http://abaababa.ouvaton.org/wipe/ (in most distributions)
    [2] http://wipe.sourceforge.net/ (yet another wipe)
    [3] http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
    
"""

import sys
import random
import urllib # We could use pycurl for greater functionality, eg. re-directs.
import urlparse
from optparse import OptionParser
from subprocess import call


def stream_mutate_xor(data, keystream, F):
    """ XOR data with a mutated keystream (generator).
        Can you see my Fnord?
    """
    for n, c in enumerate(data):
        yield chr(ord(c) ^ F(ord(keystream.next()), n))

def cyclic_range(start, stop=None, step=1):
    """ Cyclicly sweep a defined range endlessly. This could be used as is,
        as an secret ingredient.
    """
    if not stop:
        stop = start
        start = 0
    
    pointers = xrange(start, stop)
    m = len(pointers)
    index = 0
    while True:
        yield pointers[index]
        index = (index + step) % m

def circular_buffer(data):
    """ A generator that sweeps circularly through the data buffer.
    """
    m = len(data)
    index = 0
    while True:
        yield data[index]
        index = (index + 1) % m

def prng_iter(seed, offset):
    """ This is a Pseudo-Random Number Generator used as a secret ingredient.
    """
    random.seed(seed)
    for i in range(offset):
        null = random.randint(0, 255)
    
    while True:
        yield chr(random.randint(0, 255))

def iter_read(f, iter):
    """ Read one byte at a time from a file or StingIO object, position 
        determined by an iterator.
    """
    while True:
        f.seek(iter.next())
        yield f.read(1)

def iters_demux(*iters):
    """ Demultiplex multiple iterators.
    """
    m = len(iters)
    index = 0
    while True:
        yield iters[index].next()
        index = (index + 1) % m

def simple_function(k, n):
    """ The simple function secret ingredient described in the pfse.pdf.
    """
    if (n % 2) == 0:
        return((k + 3) % 255)
    else:
        return((k + 5) % 255)

def memory_function(k, n, registers=[0,1,2,3,4,5,6,7]):
    """ This is a secret ingredient with 8 bytes of memory. 
    """
    index = n % 8
    r = registers[index]
    registers[index] = k
    
    if (n % 5 == 0):
        return(r)
    else:
        return(k)

def null_mutation(k, n):
    """ The mutation function that does nothing.
        Thus could be written as, null_mutation = lambda k, n: k.
    """
    return(k)


if __name__ == '__main__':
    
    version = '%prog 1.0'
    parser = OptionParser(usage='%prog [options]',
                          version=version)
    
    parser.add_option('-c',
                      '--command',
                      dest='command',
                      action='store',
                      type='string',
                      default='xcode',
                      help='one of xcode, wipe [default: xcode]')
    
    parser.add_option('-i',
                      '--input',
                      dest='input',
                      action='store',
                      type='string',
                      help='input filename')
    
    parser.add_option('-k',
                      '--key',
                      dest='key',
                      action='store',
                      type='string',
                      default='',
                      help='key filename')
    
    parser.add_option('-o',
                      '--output',
                      dest='output',
                      action='store',
                      type='string',
                      default='',
                      help='output filename')
    
    parser.add_option('-r',
                      '--recipe',
                      dest='recipe',
                      action='store',
                      type='string',
                      default='',
                      help='key recipe')
    
    parser.add_option('-s',
                      '--secret-ingredient',
                      dest='secret_ingredient',
                      action='store',
                      type='int',
                      default=2,
                      help='secret ingredient, a number (0..3) [default: 2]')
    
    options, args = parser.parse_args()
    
    ingredients = []
    
    if options.recipe:
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(options.recipe)
        ingredient_resources = fragment.split('#')
    
        for url in ingredient_resources:
            try:
                ingredients.append(circular_buffer(urllib.urlopen(url).read()))
            except:
                pass
    
    if options.secret_ingredient > 3:
        options.secret_ingredient = 0
    
    if options.command in ('xcode',):
    
        # For pure data secret ingredients we don't need a keystream mutation
        # function (algorithm), $K'_i = K_i$.
        F = null_mutation
        
        if options.secret_ingredient == 0:
            # If the secret ingredient is simply static data, it gets added to our
            # other ingredients. This can be any file, an image file preverbly.
            ingredients.append(circular_buffer(open(sys.argv[0]).read()))
        
        if options.secret_ingredient == 1:
            # If the secret ingedient is a data producing function, we will also
            # add it to our other ingredients.
            ingredients.append(prng_iter(31337, 1155))
        
        # Mixing the ingredients to produce the intermediate keystream $K_i$. 
        K_i = iters_demux(*ingredients)
        
        if options.secret_ingredient == 2:
            # Ideally our secret ingredient should be an function (algorithm).
            # The attacker will then have to guess/compute this secret function.
            # In this case I could show that the secret-ingredient-space is at
            # least $Aleph_0$, maybe even $Aleph_1$.
            F = simple_function
        
        if options.secret_ingredient == 3:
            F = memory_function
    
    if options.command in ('xcode',):
        if not options.input or not options.output:
            print('Both input and output filenames are required.\n')
            parser.print_help()
            sys.exit(1)
        
        try:
            output = open(options.output, 'w')
        except Exception, error:
            print('There is some issue with your output file.')
            print(str(error))
            sys.exit(1)
        
        # This is just for evaluation purposes, a real application dealing with 
        # large input files will make use of block reads and stream the file.
        try:
            data = open(options.input, 'r').read()
        except Exception, error:
            print('There is some issue with your input file.')
            print(str(error))
            sys.exit(1)
        
        # This piece of code XOR the data with $K'_i = F(K_i)$.
        for c in stream_mutate_xor(data, K_i, F):
            output.write(c)
        
        output.close()
    
    if options.command in ('wipe',):
        command = 'wipe %s' % options.input
        try:
            exit_code = call(command, shell=True)
        except Exception, error:
            exit_code = 127
        
        if exit_code != 0:
            print('You need to install a secure-wipe utility, either http://abaababa.ouvaton.org/wipe or http://wipe.sourceforge.net/')
