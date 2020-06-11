from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.PublicKey import RSA

from os.path import join
import asn1
import aux.dump
import sys

def dump_tag(tab_ba):
    decoder = asn1.Decoder()
    decoder.start(tab_ba)
    aux.dump.pretty_print(decoder, sys.stdout)


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


def saveFile(data, filename):
    d = (bytes(data))
    with open(join('data',filename), 'wb') as fout:
        fout.write(d)
        fout.close()

def load_file( filename):
    with open(join('data',filename), 'rb') as fin:
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
    certs = pkcs7._pkcs7.d.sign.cert

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