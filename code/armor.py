""" Encode and decode ASCII armored text.
"""
import base64
import textwrap


ARMOR_TYPES = {
    'message': ('-----BEGIN PFSE MESSAGE-----', '-----END PFSE MESSAGE-----'),
    'recipe': ('-----BEGIN PFSE RECIPE-----', '-----END PFSE RECIPE-----'),
    'dh-publickey': ('-----BEGIN DH PUBLICKEY-----', '-----END DH PUBLICKEY-----'),
}

ARMOR_LOOKUP = {}
for type_, (header, footer) in ARMOR_TYPES.items():
    ARMOR_LOOKUP[header] = type_


def armor(blob, type='message', width=80):
    """ Generate ASCII armored text.
    """
    header, footer = ARMOR_TYPES.get(type, (None, None))
    if header:
        text = '\n'.join(textwrap.wrap(base64.b64encode(blob).decode('ascii'), width=width))
    else:
        text = ''

    return header + '\n' + text + '\n' + footer


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
