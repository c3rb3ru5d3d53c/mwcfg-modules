import logging

from malduck.extractor import Extractor
from malduck import uint32
import base64
from dotnetfile import DotNetPE

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

    @staticmethod
    def get_stream_data(pe, stream):
        addr = pe.dotnet_stream_lookup[stream].address
        size = pe.dotnet_stream_lookup[stream].size
        return pe.get_data(addr, size)

    @staticmethod
    def get_user_string(data, offset):
        result = data[offset+1:].split(b'\x00\x00')[0] + b'\x00'
        if result[0] == 0: return ''
        return result.decode('utf-16')

    @Extractor.extractor('bytecode_0')
    def bytecode_0(self, p, addr):
        match_buffer = p.readv(addr, 47)
        pe = DotNetPE(p.readp(0, p.length))
        data = self.get_stream_data(pe, '#US')
        hosts_ciphertext = self.get_user_string(data, uint32(other=match_buffer[1:1+3] + b'\x00'))
        key = self.get_user_string(data, uint32(other=match_buffer[31:31+3] + b'\x00'))
        id_ciphertext = self.get_user_string(data, uint32(other=match_buffer[11:11+3] + b'\x00'))
        message = self.get_user_string(data, uint32(other=match_buffer[21:21+3] + b'\x00'))
        hosts = self.decrypt(hosts_ciphertext, key).split('|')
        id_0 = self.decrypt(id_ciphertext, key)
        return {
            'family': self.family,
            'hosts': hosts,
            'id': id_0,
            'message': message
        }
        
