import logging

from malduck.extractor import Extractor
from malduck.pe import MemoryPEData

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class BitterZxxZ(Extractor):

    """
    Bitter APT ZxxZ Configuration Extractor
    """

    family     = 'bitter_zxxz'
    yara_rules = 'zxxz',

    @staticmethod
    def decrypt(key, data):
        data = bytearray(data)
        keylen = len(key)
        keypos = 0
        for i in range(0, len(data)):
            if data[i] == 0x00:
                break
            if keypos >= keylen:
                keypos = 0
            data[i] = data[i] ^ int(key[keypos].encode('utf-8').hex(), base=16)
            keypos += 1
        return data.decode('utf-8').rstrip('\x00')

    @Extractor.extractor('config_0')
    def config_0(self, p, addr):
        if p.memory:
            c2_host_key_va = p.uint32v(addr + 34)
            c2_host_key    = p.asciiz(c2_host_key_va).decode('utf-8')
            c2_domain_va = p.uint32v(addr + 39)
            c2_domain_encrypted = p.readv(c2_domain_va, 253)
            c2_domain = self.decrypt(c2_host_key, c2_domain_encrypted)
            return {
                'family':  self.family,
                'domain': c2_domain
            }
