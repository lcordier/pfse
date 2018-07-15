#!/usr/bin/env python

"""
    Pretty Frecking Strong Encryption
    
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
"""
import sys
import optparse
import subprocess
import datasource as ds


if __name__ == '__main__':
    
    parser = optparse.OptionParser()
    
    parser.add_option('-i',
                      '--input',
                      dest='input',
                      action='store',
                      type='string',
                      help='input filename')
    
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
                      default='recipe.csv',
                      help='recipe.csv filename')
    
    parser.add_option('-p',
                      '--passphrase',
                      dest='passphrase',
                      action='store',
                      type='string',
                      default='',
                      help='a security sentence')
    
    parser.add_option('-w',
                      '--wipe',
                      dest='wipe',
                      action='store_true',
                      default=False,
                      help='securely wipe the input file')
    
    options, args = parser.parse_args()
    
    if not (options.input and options.output and options.passphrase):
        parser.print_help()
        sys.exit()
    
    keys = ds.bake(options.recipe)
    
    if options.passphrase:
        key = ds.passphrase(options.passphrase)
        keys.append(key)
    
    input = ds.FileSource(options.input)
    
    output = open(options.output, 'wb')
    output.write(ds.xor_multi(input, keys).data())
    output.close()
    
    if options.wipe:
        command = 'wipe %s' % options.input
        try:
            subprocess.call(command, shell=True)
        except:
            print('You need to install a secure-wipe utility, either')
            print('http://lambda-diode.com/software/wipe/ or')
            print('http://wipe.sourceforge.net/')
