import logging
import re
from malduck.extractor import Extractor
from malduck.pe import MemoryPEData
from hexdump import hexdump
from binascii import unhexlify
from malduck import rc4

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5 & zm00"
__version__ = "1.0.0"

class DarkCloud(Extractor):

    """
    DarkCloud Stealer Config Extractor
    """

    family     = 'darkcloud'
    yara_rules = 'darkcloud',

    r_ciphertext = re.compile(r'^[A-F0-9]+$')
    r_email = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(?:\.[A-Z|a-z]{2,})+')

    data = []

    def is_ciphertext(self, string):
        return bool(re.search(self.r_ciphertext, string))

    def extract_emails(self, strings):
        emails = []
        for string in strings:
            match = re.match(self.r_email, string)
            if match: emails.append(match.group(0))
        return list(set(emails))

    @Extractor.extractor('key_0')
    def key_0(self, p, addr):
        string_va = p.uint32v(addr + 1)
        string = p.utf16z(string_va).decode('utf-8')
        if len(string) > 0:
            self.data.append(string)

    def decrypt_strings(self):
        strings = []
        for i in range(0, len(self.data)):
            if self.is_ciphertext(self.data[i]) is True:
                string = rc4(self.data[i+1].encode(), bytes.fromhex(self.data[i]))
                if string.isascii(): strings.append(string.decode('utf-8'))
        return strings

    @Extractor.final
    def extract_config(self, p):
        if p.memory:
            strings = self.decrypt_strings()
            emails = self.extract_emails(strings)
            if len(emails) > 0:
                return {
                    'family': self.family,
                    'emails': emails
                }
