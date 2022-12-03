import logging

from malduck.extractor import Extractor
from malduck.pe import PE
from malduck import asciiz
import base64
import clr
import dnfile
import dotnetfile

log = logging.getLogger(__name__)

__author__  = "@c3rb3ru5d3d53c"
__version__ = "1.0.0"

class Redline(Extractor):
    """
    Redline Stealer Config Extractor
    """

    family     = 'redline'
    yara_rules = ('redline',)

    @staticmethod
    def decrypt(ciphertext, key):
        key = key.encode()
        ciphertext = base64.b64decode(ciphertext)
        plaintext = []
        for i in range(0, len(ciphertext)):
            plaintext.append(ciphertext[i] ^ key[i % len(key)])
        plaintext = bytes(plaintext).decode('utf-8')
        return base64.b64decode(plaintext).decode('utf-8')

    @Extractor.final
    def string_0(self, p):
        return {
            'family': self.family,
            'hosts': ['placeholder']
        }
