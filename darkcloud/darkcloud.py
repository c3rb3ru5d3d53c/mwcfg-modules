import logging
import re
from malduck.extractor import Extractor
from malduck.pe import MemoryPEData
from hexdump import hexdump
from binascii import unhexlify

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class DarkCloud(Extractor):

    """
    DarkCloud Stealer Config Extractor
    """

    family     = 'darkcloud'
    yara_rules = 'darkcloud',

    r_key = re.compile(r'^[A-F0-9]+$')

    keys = []
    g_strings = []

    def is_key(self, string):
        return bool(re.search(self.r_key, string))

    @Extractor.extractor('key_0')
    def key_0(self, p, addr):
        string_va = p.uint32v(addr + 1)
        string = p.utf16z(string_va).decode('utf-8')
        if len(string) > 0:
            self.g_strings.append(string)
        if self.is_key(string) is True:
            self.keys.append(string)

    @Extractor.final
    def extract_config(self, p):
        if p.memory:
            ciphertext = [x for x in self.g_strings if self.is_key(x) is False]
            ciphertext = [x for x in ciphertext if x.count(" ") == 0]
            self.keys = [unhexlify(x) for x in self.keys]
            print(self.keys)
        # return {'family': self.family}
