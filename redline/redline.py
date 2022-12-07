import logging

from malduck.extractor import Extractor
from malduck.pe import PE
from malduck import asciiz
from malduck import uint32
import base64
from dotnetfile import DotNetPE
from hexdump import hexdump

log = logging.getLogger(__name__)

__author__  = "@c3rb3ru5d3d53c"
__version__ = "1.0.0"

class Redline(Extractor):
    """
    Redline Stealer Config Extractor
    """

    family     = 'redline'
    yara_rules = ('redline',)
    hosts_ciphertext_offset = None
    key_offset = None

    @staticmethod
    def decrypt(ciphertext, key):
        key = key.encode()
        ciphertext = base64.b64decode(ciphertext)
        plaintext = []
        for i in range(0, len(ciphertext)):
            plaintext.append(ciphertext[i] ^ key[i % len(key)])
        plaintext = bytes(plaintext).decode('utf-8')
        return base64.b64decode(plaintext).decode('utf-8')

    @staticmethod
    def get_stream_data(pe, stream):
        addr = pe.dotnet_stream_lookup[stream].address
        size = pe.dotnet_stream_lookup[stream].size
        return pe.get_data(addr, size)

    @staticmethod
    def get_user_string(data, offset):
        return (data[offset+1:].split(b'\x00\x00')[0] + b'\x00').decode('utf-16')

    @Extractor.extractor('bytecode_0')
    def bytecode_0(self, p, addr):
        buff = p.readv(addr, 47)
        hosts_ciphertext_offset = uint32(other=buff[1:1+3] + b'\x00')
        key_offset = uint32(other=buff[31:31+3] + b'\x00')
        pe = DotNetPE(p.readp(0, p.length))
        data = self.get_stream_data(pe, '#US')
        ciphertext = self.get_user_string(data, hosts_ciphertext_offset)
        key = self.get_user_string(data, key_offset)
        hosts = self.decrypt(ciphertext, key).split('|')
        return {
            'family': self.family,
            'hosts': hosts
        }
        