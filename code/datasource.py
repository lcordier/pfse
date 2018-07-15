import csv
import scrypt
import hashlib
import numbers
import operator
import requests
import functools
import primesieve
#import pandas as pd


class BasicSource(object):
    """ Encapsulate raw data.
    """
    def __init__(self, block):
        if isinstance(block, basestring):
            self._data = [ord(x) for x in block]
        else:
            self._data = [x % 256 for x in block]
        self._size = len(self._data)
    
    def __iter__(self):
        return iter(self._data)
    
    def __getitem__(self, index):
        if isinstance(index, numbers.Integral):
            return(self._data[index % self._size])
        elif isinstance(index, slice):
            return self._data[index]
        else:
            return NotImplemented
    
    def __len__(self):
        return self._size
    
    def __eq__(self, other):
        if len(self) != len(other):
            return False
        else:
            return all(a == b for a, b in zip(self, other))
    
    def __hash__(self):
        return functools.reduce(operator.xor, self, 0)
    
    def __add__(self, other):
        return BasicSource([x for x in self] + [x for x in other])
    
    def __repr__(self):
        # Need reprlib here.
        return 'BasicSource({})'.format(self._data)
    
    def data(self):
        return ''.join(chr(x) for x in self)


class WebSource(BasicSource):
    """ Encapsulate a partial web resource.
    """
    def __init__(self, url, start, stop=None, user_agent=''):
        if stop:
            headers = {'Range': 'bytes={}-{}'.format(start, stop)}
            response = requests.get(url, headers=headers, stream=True)
        else:
            response = requests.get(url)
            
        if response.status_code in [200, 206]:
            super(WebSource, self).__init__(response.content)
    
    def __repr__(self):
        # Need reprlib here.
        return 'WebSource({})'.format(self._data)


class FileSource(BasicSource):
    """ Encapsulate data from files.
    """
    def __init__(self, path, start=0, stop=None):
        input = open(path, 'rb')
        input.seek(start)
        
        if stop:
            block = input.read(stop - start)
        else:
            block = input.read()
        
        input.close()
        super(FileSource, self).__init__(block)
    
    def __repr__(self):
        # Need reprlib here.
        return 'FileSource({})'.format(self._data)


class PasswordSource(BasicSource):
    """ Improve the entropy of a password.
    """
    def __init__(self, password):
        hash = hashlib.sha512(password).hexdigest()
        block = [int(x, 16) for x in [hash[i:i+2] for i in range(0, len(hash), 2)]]
        super(PasswordSource, self).__init__(block)


class HexdigestSource(BasicSource):
    """ Encapsulate the hexdigest of an hash.
    """
    def __init__(self, hash):
        block = [int(x, 16) for x in [hash[i:i+2] for i in range(0, len(hash), 2)]]
        super(HexdigestSource, self).__init__(block)


#class OEISSource(BasicSource):
#    """ The On-Line Encyclopedia of Integer Sequences.
#        
#        http://oeis.org/
#    """
#    def __init__(self, sequence_name):
#        block = [int(x) % 256 for x in pd.read_html('http://oeis.org/{}/list'.format(sequence_name), skiprows=1)[2][2].values]
#        super(OEISSource, self).__init__(block)


def xor(message, key):
    """ Xor a message with a key.
    """
    return BasicSource([operator.xor(m, key[i]) for i, m in enumerate(message)])


def xor_multi(message, keys):
    return functools.reduce(xor, keys, message)


def xor_stream(a, b):
    """ Xor two streams.
    """
    while True:
        yield(operator.xor(a.next(), b.next()))


def passphrase(phrase):
    """ Turn a passphrase into a concatenation of word hashes. 
    """
    return BasicSource(functools.reduce(operator.add, [PasswordSource(word) for word in phrase.split()], BasicSource([0]))[1:])


def passphrase2(phrase, salt, n=1):
    """ Turn a passphrase into a concatenation of word hashes.
        
        https://en.wikipedia.org/wiki/Key_derivation_function
        
        Make it slightly more difficult to generate and reverse these hashes, think rainbow tables.
    """
    words = phrase.split()
    assert len(words) >= 2, "A pass-phrase with two or more words are required."
    
    hashes = []
    sha512 = hashlib.sha512()
    sha512.update(salt)
    
    for word in words:
        for i in range(n):
            sha512.update(sha512.hexdigest())
        
        sha512.update(word)
        hashes.append(sha512.hexdigest())
        
    return BasicSource(functools.reduce(operator.add, [HexdigestSource(hash) for hash in hashes], BasicSource([0]))[1:])


class ScryptHash(object):
    def __init__(self, password, salt):
        self.hash = scrypt.hash(password, salt)
    
    def update(self, data):
        self.hash = scrypt.hash(data, self.hash)
    
    def hexdigest(self):
        return self.hash.encode('hex')


def passphrase3(phrase, salt, n=1):
    """ Turn a passphrase into a concatenation of word hashes.
        
        https://en.wikipedia.org/wiki/Key_derivation_function
        
        Make it slightly more difficult to generate and reverse these hashes, think rainbow tables.
    """
    words = phrase.split()
    #assert len(words) >= 2, "A pass-phrase with two or more words are required."
    
    hashes = []
    shash = ScryptHash('', salt)
    
    for word in words:
        for i in range(n):
            shash.update(shash.hexdigest())
        
        shash.update(word)
        hashes.append(shash.hexdigest())
        
    return BasicSource(functools.reduce(operator.add, [HexdigestSource(hash) for hash in hashes], BasicSource([0]))[1:])


def bbs(p, q, s):
    """
        http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n
        https://en.wikipedia.org/wiki/Blum_Blum_Shub
    """
    assert (p % 4) == 3, 'Bad prime: {}'.format(p)
    assert (q % 4) == 3, 'Bad prime: {}'.format(q)
    m = p * q
    x = s
    while True:
        x = (x ** 2) % m
        yield bin(x).count('1') % 2


def byte_stream(bit_stream):
    """ Generate a stream of bytes from a stream of bits.
    """
    while True:
        yield sum(bit_stream.next() * (i ** 2) for i in range(8))


def source_stream(block):
    """
    """
    index = 0
    while True:
        yield block[index]
        index += 1


def find_repeat(stream, n=10, limit=10 ** 6):
    """
    """
    test = [stream.next() for i in range(n)]
    acc = test[:]
    acc.pop(0)
    acc.append(stream.next())
    index = 0
    
    while n < limit and test != acc:
        acc.pop(0)
        acc.append(stream.next())
        index += 1
    
    return(index)


def bake(recipe_path):
    """ Bake a recipe.csv into a set of keys.
        
        "file",,,errata.txt
        "www",1,109,http://www.louiscordier.com/louis.jpg
        "passphrase","my voice is my passport, verify me"
    """
    recipe = open(recipe_path, 'r')
    reader = csv.reader(recipe)
    keys = []
    for row in reader:
        type = row[0]
        if type in ['file']:
            _, start, stop, path = row
            start = int(start or 0)
            stop = int(stop or -1)
            if stop < 0:
                stop = None
            key = FileSource(path, start, stop)
        
        if type in ['www']:
            _, start, stop, url = row
            start = int(start or 0)
            stop = int(stop or -1)
            if stop < 0:
                stop = None
            key = WebSource(url, start, stop)
        
        if type in ['passphrase']:
            _, phrase = row
            key = passphrase(phrase)
        
        keys.append(key)
    
    return(keys)


primes = filter(lambda x: x % 4 == 3, primesieve.generate_primes(10 ** 6))
