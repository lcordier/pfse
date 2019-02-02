#!/usr/bin/env python

""" Bake a recipe into a symmetric key.
"""
import base64
import hashlib
import io
import textwrap
import requests


ARMOR_TYPES = {
    'message': ('-----BEGIN PFSE MESSAGE-----', '-----END PFSE MESSAGE-----'),
    'recipe': ('-----BEGIN PFSE RECIPE-----', '-----END PFSE RECIPE-----')
}

ARMOR_LOOKUP = {}
for type_, (header, footer) in ARMOR_TYPES.items():
    ARMOR_LOOKUP[header] = type_


class IngredientError(Exception):
    pass


class Ingredient(object):
    """ Wrap an ingredient.
    """
    def __init__(self, ingredient):
        self.ingredient = ingredient
        self.n = len(ingredient)
        self.index = 0

    def __iter__(self):
        while True:
            yield chr(self.ingredient[self.index % self.n]).encode()
            self.index += 1

    def __next__(self):
        value = self.ingredient[self.index % self.n]
        self.index += 1
        return(chr(value).encode())

    def seek(self, index):
        self.index = index


class SecretIngredient(Ingredient):
    """ Wraps a secret ingredient.
    """
    pass


def fetch_ingredient(ingredient):
    """ Fetch a single ingredient.
    """
    ingredient = ingredient.strip()
    if not ingredient.lower().startswith('http'):
        return None

    if '#' in ingredient:
        url, offset_size = ingredient.rsplit('#', 1)
    else:
        url, offset_size = ingredient, '0,0'

    offset, size = [int(i) for i in offset_size.split(',', 1)]

    # Consider setting a custom User-Agent.
    if size > 0:
        headers = {'Range': 'bytes={}-{}'.format(offset, offset + size - 1)}
    else:
        headers = {'Range': 'bytes={}-'.format(offset)}

    response = requests.get(url, headers=headers)

    if response.status_code in [206]:
        data = response.content
        if size:
            if len(data) != size:
                raise IngredientError('Partial download size mismatch.')
        return Ingredient(data)
    elif response.status_code in [200]:
        data = response.content
        if size and len(data) > size:
            data = data[offset:offset + size]
        return Ingredient(data)
    else:
        raise IngredientError('Unexpected status code: {}.'.format(response.status_code))


def fetch_ingredients(recipe):
    """ Fetch all the ingredients of a recipe.
    """
    ingredients = []
    for item in recipe.splitlines():
        ingredient = fetch_ingredient(item)
        if ingredient:
            ingredients.append(ingredient)

    return ingredients


def secret_ingredient(path, offset=0, size=0):
    """ Read the local secret ingredient.
    """
    with open(path, 'rb') as f:
        f.seek(offset)
        if size:
            data = f.read(size)
        else:
            data = f.read()

    return SecretIngredient(data)


def bake(ingredients, passphrase=b'', offset=0, blocks=1, strong=True):
    """ Bake a key from the ingredients.
    """
    if strong:
        if SecretIngredient not in [type(ingredient) for ingredient in ingredients]:
            raise IngredientError('At least one SecretIngredient is needed.')

    key = io.BytesIO()
    sha512 = hashlib.sha512()
    sha512.update(passphrase)  # Make brute-force a bit harder.

    for idx in range(offset):
        for ingredient in ingredients:
            sha512.update(next(ingredient))

    for idx in range(blocks):
        for ingredient in ingredients:
            sha512.update(next(ingredient))

        key.write(sha512.digest())

    key.seek(0)
    return(key.read())


def key_size(message):
    """ Calculate the desired key size in 64 byte blocks.
    """
    return (len(message) // 64) + 1


def xor(message, key):
    """ Xor a message with a key.
    """
    return bytes(m ^ k for m, k in zip(message, key))


def armor(blob, type='message', width=100):
    """ Generate ASCII armored text.
    """
    header, footer = ARMOR_TYPES.get(type, (None, None))
    if header:
        text = '\n'.join(textwrap.wrap(base64.b64encode(blob).decode('ascii'), width=width))
    else:
        text = ''

    return header + '\n\n' + text + '\n' + footer


def dearmor(text):
    """ Decode embedded ASCII armored texts.
    """
    blobs = []
    state = None
    for line in text.splitlines():
        if state is None:
            for header, type in ARMOR_LOOKUP.items():
                if header in line:
                    state = type
                    footer = ARMOR_TYPES[type][1]
                    payload = ''
        else:
            if footer not in line:
                payload += line
            else:
                if state in ['recipe']:
                    blobs.append((state, base64.b64decode(payload).decode()))
                else:
                    blobs.append((state, base64.b64decode(payload)))
                state = None

    return blobs


if __name__ == '__main__':

    recipe = """
    http://www.louiscordier.com/louis.jpg#0,100
    http://www.louiscordier.com/die_manne.jpg#1000,100

    Note: Use that image of me at Jacques's bday party as your secret ingredient.
    """

    message = 'This is a test.'.encode()
    passphrase = 'A really long passphrase'.encode()
    ingredients = fetch_ingredients(recipe)
    ingredients.append(secret_ingredient('secret.jpg'))
    key = bake(ingredients, passphrase, blocks=key_size(message))
    cipher = xor(message, key)
    print(armor(cipher))
    print('')
    print(armor(recipe.encode(), type='recipe'))
    print('')
    print(dearmor('some text' + armor(cipher) + '\n' + armor(recipe.encode(), type='recipe')))
