#!/usr/bin/env python

""" Bake a recipe into a symmetric key.
"""
from __future__ import print_function
import hashlib
import io
import requests


RECIPE = """
http://www.louiscordier.com/louis.jpg#0,100
http://www.louiscordier.com/die_manne.jpg#1000,100
"""


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


def fetch_ingredient(ingredient):
    """ Fetch a single ingredient.
    """
    ingredient = ingredient.strip()
    if not ingredient:
        return None

    if '#' in ingredient:
        url, offset_size = ingredient.rsplit('#', 1)
    else:
        url, offset_size = ingredient, '0,0'

    offset, size = [int(i) for i in offset_size.split(',', 1)]

    if size > 0:
        headers = {'Range': 'bytes={}-{}'.format(offset, offset + size - 1)}
    else:
        headers = {'Range': 'bytes={}-'.format(offset)}

    response = requests.get(url, headers=headers)

    if response.status_code in [206]:
        data = response.content
        if size:
            assert len(data) == size, "Partial download size mismatch."
        return Ingredient(data)
    elif response.status_code in [200]:
        data = response.content
        if size and len(data) > size:
            data = data[offset:offset + size]
        return Ingredient(data)


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

    return Ingredient(data)


def bake(ingredients, offset=0, blocks=1):
    """ Bake a key from the ingredients.
    """
    key = io.BytesIO()
    sha512 = hashlib.sha512()

    for idx in range(offset):
        for ingredient in ingredients:
            sha512.update(next(ingredient))

    for idx in range(blocks):
        for ingredient in ingredients:
            sha512.update(next(ingredient))

        key.write(sha512.digest())

    key.seek(0)
    return(key.read())


if __name__ == '__main__':
    a = fetch_ingredients(RECIPE)
