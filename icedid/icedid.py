import logging

from malduck.extractor import Extractor
from malduck.pe import PE
from malduck import asciiz

log = logging.getLogger(__name__)

__author__  = "4rchib4ld"
__version__ = "1.0.0"

class icedid(Extractor):

    """
    IcedID C2 Domain Configuration Extractor
    """

    family     = 'icedid'
    yara_rules = 'icedid',

    @staticmethod
    def extractPayload(pe):
        """
        Extracting the payload from the .data section
        """
        for section in pe.sections:
            if ".data" in str(section.Name):
                data = section.get_data()
                payload = asciiz(data[4:])
                return payload

    @Extractor.rule
    def icedid(self, p, matches):
        obfuscationCode = matches.elements["obfuscationCode"][0][2]
        xorCountValue = obfuscationCode[3] ## Getting this values dynamically because... you never know
        countValue = obfuscationCode[-1]
        pe_rep = PE(data=p)
        payload = self.extractPayload(pe_rep)
        decrypted = bytearray()
        for i in range(countValue):
            try:
                decrypted.append(payload[i + xorCountValue] ^ payload[i])
            except IndexError:
                pass
        c2 = asciiz(decrypted)
        config = {
            'family': self.family,
            'url': c2.decode()
        }
        return config
