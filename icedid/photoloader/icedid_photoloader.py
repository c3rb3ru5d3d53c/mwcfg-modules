import logging

from malduck.extractor import Extractor
from malduck.pe import PE
from malduck import asciiz

log = logging.getLogger(__name__)

__author__  = "4rchib4ld"
__version__ = "1.0.0"

class IcedIDPhotoLoader(Extractor):

    """
    IcedID PhotoLoader C2 Domain Configuration Extractor
    """

    family     = 'icedid_photoloader'
    yara_rules = ('icedid_photoloader',)

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
    def icedid_photoloader(self, p, matches):
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
        if len(c2) > 0:
            return {
                'family': self.family,
                'urls': [c2.decode('utf-8')]
            }
        return None
