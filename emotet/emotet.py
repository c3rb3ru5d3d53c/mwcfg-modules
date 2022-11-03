import logging

from malduck.extractor import Extractor
from ipaddress import IPv4Address

log = logging.getLogger(__name__)

__author__  = "t-mtsmt"
__version__ = "1.0.0"

class Emotet(Extractor):

    """
    Emotet C2 Configuration Extractor
    """

    family     = 'emotet'
    yara_rules = 'emotet',

    def swap32(self, x):
        return int.from_bytes(x.to_bytes(4, byteorder='little'), byteorder='big', signed=False)

    @Extractor.extractor('ref_c2')
    def ref_c2(self, p, addr):
        enc_ip       = p.uint32v(addr + 4)
        enc_port     = p.uint32v(addr + 11)
        xor_key_ip   = p.uint32v(addr + 19)
        xor_key_port = p.uint32v(addr + 27)

        ip = IPv4Address(self.swap32(enc_ip ^ xor_key_ip))
        port     = (enc_port ^ xor_key_port) >> 0x10
        is_valid = (enc_port ^ xor_key_port) & 0xffff

        if is_valid == 0:
            return None

        c2 = f'{ip}:{port}'
        return {'family': 'emotet', 'c2': [c2]}