import logging
import malduck

from malduck import disasm, p32
from malduck.extractor import Extractor

log = logging.getLogger(__name__)

__author__  = "CERT.pl"
__version__ = "1.0.0"

class Citadel(Extractor):

    """
    Citadel Configuration Extractor
    """
    
    family     = "citadel"
    yara_rules = "citadel",

    @Extractor.extractor("briankerbs")
    def citadel_found(self, p, addr):
        log.info('[+] `Coded by Brian Krebs` str @ %X' % addr)
        return {'family': 'citadel'}

    @Extractor.weak
    @Extractor.extractor
    def cit_salt(self, p, addr):
        salt = p.uint32v(addr - 8)
        log.info('[+] Found salt @ %X - %x' % (addr, salt))
        return {'salt': salt}

    @Extractor.extractor
    def cit_login(self, p, addr):
        log.info('[+] Found login_key xor @ %X' % addr)
        hit = p.uint32v(addr + 4)
        if p.is_addr(hit):
            return {'login_key': p.asciiz(hit)}
        hit = p.uint32v(addr + 5)
        if p.is_addr(hit):
            return {'login_key': p.asciiz(hit)}

    @Extractor.extractor
    def cit_aes_xor(self, p, addr):
        log.info('[+] Found aes_xor key @ %X' % addr)
        r = []
        for c in disasm(p.readv(addr, 40), addr):
            if len(r) == 4:
                break
            if c.mnem == 'xor':
                r.append(c.op2.value)
        return {'aes_xor': malduck.enhex(b''.join(map(p32, r)))}

    @Extractor.weak
    @Extractor.extractor
    def cit_getpes(self, p, addr):
        log.info('[+] pesettings found near @ %X' % addr)
        oss = []
        for c in disasm(p.readv(addr-20, 100), addr-20):
            if len(oss) == 2:
                break
            elif c.mnem == 'lea':
                oss.append(abs(c.op2.value))

        off = oss[0] - oss[1]
        return {'key_off': abs(off)}

    @Extractor.weak
    @Extractor.extractor
    def cit_base_off(self, p, addr):
        var_bc = int(p.uint32v(addr + 3))
        var_lk = int(p.uint32v(addr + 30))
        offset = var_bc - var_lk
        return {'key_off': abs(offset)}
