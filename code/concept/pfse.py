#!/usr/bin/env python
"""
    Pretty Frecking Strong Encryption
    
    Author: Louis Cordier <lcordier@gmail.com>
    Copyright: (c) 2009, All rights reserved.
    Last Modified: 2009-10-20
    
    This program focuses on the key distribution problem of one-time pads. 
    Instead of distributing a key we distribute a recipe to make a key. 
    Thus a size-bounded recipe can be turned into an size-unbounded key.
    For example a 5 characters recipe can be turned into a 1TB key.
    Given a publicly shared recipe and a small shared secret (ingredient)
    the generated key can be concidered random for all practical purposes.
    
    Consider using wipe [1] or ya-wipe [2] to securely delete the message
    when you are done encrypting it. See also Peter Gutmann's paper
    "Secure Deletion of Data from Magnetic and Solid-State Memory" [3] for
    reasons why.
    
    [1] http://lambda-diode.com/software/wipe/ (in most distributions)
    [2] http://wipe.sourceforge.net/ (yet another wipe)
    [3] http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
    
"""
import pycurl
import urlparse
from StringIO import StringIO
from optparse import OptionParser
from subprocess import call
from decimal import Decimal, InvalidOperation
import psyco
psyco.full()


BLOCK_SIZE = 64*1024

def block_mutate_xor(input, output, keystream, F, data_ingredient=None, args=None):
    """ XOR input with a mutated keystream, F(K_i), and optionally with
        a data secret-ingredient.
    """
    n = 0
    i = input.read(BLOCK_SIZE)
    
    if args:
        if data_ingredient:
            while i:
                o = []
                for c in i:
                    o.append(chr(ord(c) ^ ord(data_ingredient.next()) ^ F(ord(keystream.next()), n, *args)))
                    n += 1
                
                output.write(''.join(o))
                i = input.read(BLOCK_SIZE)
        else:
            while i:
                o = []
                for c in i:
                    o.append(chr(ord(c) ^ F(ord(keystream.next()), n, *args)))
                    n += 1
                
                output.write(''.join(o))
                i = input.read(BLOCK_SIZE)
    else:
        if data_ingredient:
            while i:
                o = []
                for c in i:
                    o.append(chr(ord(c) ^ ord(data_ingredient.next()) ^ F(ord(keystream.next()), n)))
                    n += 1
                
                output.write(''.join(o))
                i = input.read(BLOCK_SIZE)
        else:
            while i:
                o = []
                for c in i:
                    o.append(chr(ord(c) ^ F(ord(keystream.next()), n)))
                    n += 1
                
                output.write(''.join(o))
                i = input.read(BLOCK_SIZE)
        

def circular_buffer(data):
    """ A generator that sweeps circularly through the data buffer.
    """
    m = len(data)
    index = 0
    while True:
        yield data[index]
        index = (index + 1) % m

def iters_demux(*iters):
    """ Demultiplex multiple iterators.
    """
    m = len(iters)
    index = 0
    while True:
        yield iters[index].next()
        index = (index + 1) % m

def parse_parameters(params):
    """ Turn a comma-seperated string into a list of values.
    """
    parameters = []
    for param in params.split(','):
        try:
            p = int(param)
        except ValueError:
            try:
                p = Decimal(param)
            except InvalidOperation:
                if param.lower().strip() == 'none':
                    p = None
                else:
                    p = param
        
        parameters.append(p)
    
    return(tuple(parameters))

def null(k, n):
    """ The mutation function that does nothing.
    """
    return(k)

if __name__ == '__main__':
    
    version = '%prog 1.1'
    parser = OptionParser(usage='%prog [options]',
                          version=version)
    
    parser.add_option('-c',
                      '--catalog',
                      dest='catalog',
                      action='store',
                      type='string',
                      default='catalog',
                      help='function catalog filename, needs to be a .py file')
    
    parser.add_option('-d',
                      '--data',
                      dest='data',
                      action='store',
                      type='string',
                      default='',
                      help='data secret-ingredient filename')
    
    parser.add_option('-f',
                      '--function',
                      dest='function',
                      action='store',
                      type='string',
                      default='',
                      help='function secret-ingredient, name in catalog')
    
    parser.add_option('-i',
                      '--input',
                      dest='input',
                      action='store',
                      type='string',
                      help='input filename')
    
    parser.add_option('-l',
                      '--limit',
                      dest='limit',
                      action='store',
                      type='int',
                      default=0,
                      help='ingredient fetch size-limit (bytes)')
    
    parser.add_option('-o',
                      '--output',
                      dest='output',
                      action='store',
                      type='string',
                      default='',
                      help='output filename')
    
    parser.add_option('-p',
                      '--parameters',
                      dest='parameters',
                      action='store',
                      type='string',
                      default='',
                      help='additional fuctional secret-ingredient parameters')
    
    parser.add_option('-r',
                      '--recipe',
                      dest='recipe',
                      action='store',
                      type='string',
                      default='',
                      help='key recipe')
    
    parser.add_option('-w',
                      '--wipe',
                      dest='wipe',
                      action='store_true',
                      default=False,
                      help='securely wipe the input file')
    
    options, args = parser.parse_args()
    
    c = options.catalog
    if c.find('.py') > -1:
        c = c.rstrip('.py')
    
    try:
        catalog = __import__(c)
    except ImportError, error:
        print('Functional catalog file not found, it needs to be a .py file.')
        raise SystemExit
    
    ingredients = []
    
    limit = options.limit
    recipe = options.recipe
    
    if recipe:
        # Shortened recipe URL?
        if recipe.count('#') < 1:
            buffer = StringIO()
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, recipe)
            curl.setopt(pycurl.FOLLOWLOCATION, 0)
            curl.setopt(pycurl.CONNECTTIMEOUT, 30)
            curl.setopt(pycurl.TIMEOUT, 300)
            curl.setopt(pycurl.WRITEFUNCTION, buffer.write)
            
            try:
                curl.perform()
            except:
                print('Network issues with the recipe URL.')
                raise SystemExit
            else:
                recipe = curl.getinfo(pycurl.REDIRECT_URL)
        
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(recipe)
        public_ingredients = fragment.split('#')
        
        for ingredient in public_ingredients:
            # We could use pycurl.CurlMulti() to speed-up downloads,
            # I prefer simpler code. ;p
            buffer = StringIO()
            
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, ingredient)
            curl.setopt(pycurl.AUTOREFERER, 1)
            curl.setopt(pycurl.FOLLOWLOCATION, 1)
            curl.setopt(pycurl.MAXREDIRS, -1)
            curl.setopt(pycurl.CONNECTTIMEOUT, 30)
            curl.setopt(pycurl.TIMEOUT, 300)
            curl.setopt(pycurl.WRITEFUNCTION, buffer.write)
            
            if limit:
                curl.setopt(pycurl.HTTPHEADER, ['Range: bytes=0-%d' % (limit-1)])
            
            try:
                curl.perform()
            except:
                pass
            else:
                if limit:
                    # Just in case the webserver doesn't honor range headers.
                    data = buffer.getvalue()[:limit]
                else:
                    data = buffer.getvalue()
                
                if data:
                    # Note, error codes are deliberately not checked,
                    # thus a 404 page could be a valid ingredient. ;)
                    ingredients.append(circular_buffer(data))
    
    if not ingredients:
        print('A proper recipe is needed.')
        raise SystemExit
    
    print('Recipe: %s' % recipe)
    
    data_ingredient = None
    
    if options.data:
        try:
            data_ingredient = circular_buffer(open(options.data, 'rb').read())
        except IOError, error:
            print('Some issues with the data secret.')
            print(str(error))
            raise SystemExit
    
    print('Data Secret: %s' % options.data)
    
    if not options.input or not options.output:
        print('Both input and output filenames are required.')
        parser.print_help()
        raise SystemExit
    else:
        try:
            input = open(options.input, 'rb')
        except Exception, error:
            print('There is some issue with your input file.')
            print(str(error))
            raise SystemExit
        
        try:
            output = open(options.output, 'wb')
        except Exception, error:
            print('There is some issue with your output file.')
            print(str(error))
            raise SystemExit
    
    if options.parameters:
        parameters = parse_parameters(options.parameters)
    else:
        parameters = None
    
    # For data secret ingredients we don't need a keystream mutation function.
    function_ingredient = null
    if options.function:
        try:
            function_ingredient = getattr(catalog, options.function)
        except:
            pass

    if function_ingredient != null:
        if parameters:
            print('Function Secret: %s(k, n, %s)\n' % (options.function, ', '.join(str(p) for p in parameters)))
        else:
            print('Function Secret: %s(k, n)\n' % (options.function,))
    else:
        print('Function Secret: null(k, n)\n')
    
    # Intermediate keystream.
    K_i = iters_demux(*ingredients)
    
    try:
        block_mutate_xor(input, output, K_i, function_ingredient, data_ingredient, parameters)
    except TypeError, error:
        print('Problems with function, %s, parameters.' % options.function)
        print(str(error))
        raise SystemExit
    
    input.close()
    output.close()
    
    if options.wipe:
        command = 'wipe %s' % options.input
        try:
            exit_code = call(command, shell=True)
        except Exception, error:
            exit_code = 127
        
        if exit_code != 0:
            print('You need to install a secure-wipe utility, either')
            print('http://lambda-diode.com/software/wipe/ or')
            print('http://wipe.sourceforge.net/')
