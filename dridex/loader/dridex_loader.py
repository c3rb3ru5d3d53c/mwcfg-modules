import logging
from malduck import ipv4
from malduck.extractor import Extractor

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class DridexLoader(Extractor):

    """
    DridexLoader Configuration Extractor
    """

    family       = 'dridex_loader'
    yara_rules   = ('dridex_loader',)
    LEN_BLOB_KEY = 40
    LEN_BOT_KEY  = 107
    botnet_rva   = None
    botnet_id    = None
    ip_count     = 0

    @Extractor.extractor('c2parse_6')
    def c2parse_6(self, p, addr):
        self.c2_rva = p.uint32v(addr+44)
        self.botnet_rva = p.uint32v(addr-7)
        self.delta = 0

    @Extractor.extractor('c2parse_5')
    def c2parse_5(self, p, addr):
        self.c2_rva = p.uint32v(addr+75)
        self.botnet_rva = p.uint32v(addr+3)
        self.botnet_id = p.uint16v(self.botnet_rva)
        self.delta = 0

    @Extractor.extractor('c2parse_4')
    def c2parse_4(self, p, addr):
        self.c2_rva = p.uint32v(addr+6)
        self.delta = 0

    @Extractor.extractor('c2parse_3')
    def c2parse_3(self, p, addr):
        self.c2_rva = p.uint32v(addr+60)
        self.delta = 2

    @Extractor.extractor('c2parse_2')
    def c2parse_2(self, p, addr):
        self.c2_rva = p.uint32v(addr+47)
        self.delta = 0

    @Extractor.extractor('c2parse_1')
    def c2parse_1(self, p, addr):
        self.c2_rva = p.uint32v(addr+27)
        self.delta = 2

    @Extractor.extractor('botnet_id')
    def get_botnet_id(self, p, addr):
        self.botnet_rva = p.uint32v(addr+23)
        self.botnet_id = p.uint16v(self.botnet_rva)

    def get_rc4_rva(self, p, rc4_decode):
        zb = p.uint8v(rc4_decode+8, 1)
        if zb:
            return p.uint32v(rc4_decode+5)
        return p.uint32v(rc4_decode+3)

    @Extractor.extractor('rc4_key_1')
    def rc4_key_1(self, p, addr):
        self.rc4_rva = self.get_rc4_rva(p, addr)

    @Extractor.extractor('rc4_key_2')
    def rc4_key_2(self, p, addr):
        self.rc4_rva = self.get_rc4_rva(p, addr)

    @Extractor.extractor('ip_count_1')
    def ip_count_1(self, p, addr):
        ip_count_rva = p.uint32v(addr + 3)
        self.ip_count = p.uint8v(ip_count_rva)

    @Extractor.extractor('ip_count_2')
    def ip_count_2(self, p, addr):
        ip_count_rva = p.uint32v(addr + 2)
        self.ip_count = p.uint8v(ip_count_rva)

    @Extractor.extractor('ip_count_3')
    def ip_count_3(self, p, addr):
        ip_count_rva = p.uint32v(addr + 2)
        self.ip_count = p.uint8v(ip_count_rva)

    @staticmethod
    def match_exists(matches, name):
        for element in matches.elements:
            if element == name:
                return True
        return False

    @Extractor.needs_pe
    @Extractor.final
    def dridex_loader(self, p):
        if p.memory:
            config = {
                'family': self.family,
                'hosts': [],
                'botnet_id': ''
            }
            if not self.ip_count or self.ip_count > 10:
                return None
            log.debug('ip_count: ' + str(self.ip_count))
            for i in range(0, self.ip_count):
                ip = ipv4(p.readv(self.c2_rva, 4))
                port = p.uint16v(self.c2_rva+4)
                log.debug('found c2 ip: ' + str(ip) + ':' + str(port))
                if ip is not None and port is not None:
                    config['hosts'].append(str(ip) + ':' + str(port))
                self.c2_rva += 6 + self.delta
            if len(config['hosts']) <= 0:
                return None
            if self.botnet_id is not None:
                log.debug('found botnet_id: ' + str(self.botnet_id))
                config['botnet_id'] = self.botnet_id
            return config
        return None
