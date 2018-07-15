

def simple(k, n):
    """ Simple example function with no additional parameters.
    """
    if (n % 2) == 0:
        return((k + 3) % 255)
    else:
        return((k + 5) % 255)

def simplep(k, n, a, b):
    """ Simple example function with additional parameters.
    """
    if (n % 2) == 0:
        return((k + a) % 255)
    else:
        return((k + b) % 255)

def memory(k, n, registers=[0,1,2,3,4,5,6,7]):
    """ This is a secret ingredient with 8 bytes of memory. 
    """
    index = n % 8
    r = registers[index]
    registers[index] = k
    
    if (n % 5 == 0):
        return(r)
    else:
        return(k)
