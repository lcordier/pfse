
Pretty Frecking Strong Encryption

Author: Louis Cordier <lcordier@gmail.com>
Copyright: (c) 2009, All rights reserved.

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


REQUIRED PACKAGES
    apt-get install python-pycurl


SYNOPSIS
    python pfse.py -h

    ./pfse.py -r http://www.google.com/#http://example.com/ingredient1#http://example.com/ingredient2 -i message.txt -o message.enc
    ./pfse.py -r http://www.google.com/#http://example.com/ingredient1#http://example.com/ingredient2 -c catalog -f simple -i message.txt -o message.enc

