from os.path import join, exists
from os import mkdir
import hashlib
import random
from smartcard.System import readers

FILES_PATH = '/tmp/dump'

def toHexString(d):
    return bytes(d).hex()

def get_readers():
    """
    Retrieves all the available readers

    Return:
        list( PCSCReader ): List of available readers
    """
    return readers()

def get_first_reader():
    """
    Retrieves the first available readers

    Return:
        Return: PCSCReader
    """
    rs = get_readers()
    print('Readers available: %s' % str(rs))
    if len(rs) > 0:
        return rs[0]

def save_file(data, filename):
    d = (bytes(data))
    if not exists(FILES_PATH):
        mkdir(FILES_PATH)
    with open(join(FILES_PATH,filename), 'wb') as fout:
        fout.write(d)
        fout.close()

def load_file( filename):
    with open(join(FILES_PATH,filename), 'rb') as fin:
        d = fin.read()
        return d

def get_certificates(pkcs7):
    from OpenSSL.crypto import _lib, _ffi, X509
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    certs = pkcs7._pkcs7.d.sign.b_sod_cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        # pycert._x509 = _lib.sk_X509_value(certs, i)
        # According to comment from @ Jari Turkia
        # to prevent segfaults use '_lib.X509_dup('
        pycert._x509 = _lib.X509_dup(_lib.sk_X509_value(certs, i))
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)

def string_to_byte(s):
    """
    Converts an hex string to the equivalent array of integer representing the parsed bytes
    :param s: The string to process
    :return: The array of integers
    """

    return [int(x, 16) for x in map(''.join, zip(*[iter(s)] * 2))]

def string_to_chars_values(s):
    """
    Converts a string to the equivalent array of integers representing the characters
    :param s: The string to process
    :return: The array of integers
    """

    return [ord(x) for x in list(s)]

def checksum(data):
    """
    Calculates a checksum used during the EAC authentication process
    :param data: The array of integer to process
    :return: The checksum value
    """

    tot = 0
    curval = 0
    weight = [7, 3, 1]
    for i in range(0, len(data)):
        ch = chr(data[i]).upper()
        if 'A' <= ch <= 'Z':
            curval = ord(ch) - ord('A') + 10
        else:
            if '0' <= ch <= '9':
                curval = ord(ch) - ord('0')
            else:
                if ch == '<':
                    curval = 0
                else:
                    raise Exception('Not a valid character')
        tot += curval * weight[i % 3]
    tot = tot % 10
    return ord('0') + tot

def get_sha1(data):
    """
    Returns the SHA1 digest of `certs` as an array of integers
    :param data: The certs to hash
    :return: The digest in form of an array of integers
    """

    m = hashlib.sha1()
    m.update(bytearray(data))

    return [ord(i) for i in list(m.digest())]

def get_rand(size):
    """
    Returns an array of `size` random integers representing bytes
    :param size: The size of the array
    :return: The array of random integers
    """

    random.seed()
    a = []
    for i in range(0, size):
        a.append(random.randint(0, 255))
    return a

