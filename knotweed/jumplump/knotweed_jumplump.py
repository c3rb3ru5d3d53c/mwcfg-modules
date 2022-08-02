import logging

import struct
import capstone
from binascii import hexlify
from malduck import rc4
from malduck.extractor import Extractor
from malduck.pe import MemoryPEData

log = logging.getLogger(__name__)

__author__  = "@jaydinbas"
__version__ = "1.0.0"

class KnotweedJumplump(Extractor):

    """
    Knotweed Jumplump Configuration Extractor
    https://gist.github.com/usualsuspect/791fc53a62d9a42836fef5e0412dd686
    https://twitter.com/jaydinbas
    """

    family     = 'knotweed_jumplump'
    yara_rules = 'knotweed_jumplump',

    pic_pattern = b"\xE8\x00\x00\x00\x00\x59\x48\x83\xE9\x05"

    @staticmethod
    def find_payload(data, p):
        DEBUG = 0
        md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        md.detail = True
        jz = None
        for insn in md.disasm(data[p:],p):
            if DEBUG:
                print("%s %s" % (insn.mnemonic,insn.op_str))
            if insn.mnemonic == "je":
                jz = insn.operands[0].imm
                break
        if not jz:
            if DEBUG:
                print("jz not found")
            return None
        payload = None
        p = jz
        for i in range(10):
            insn = next(md.disasm(data[p:],p))
            if insn.mnemonic == "jmp":
                p = insn.operands[0].imm
            elif insn.mnemonic == "call":
                payload = p
                break
            else:
                p += insn.size
        if not payload:
            return None
        else:
            payload += 5
            return payload

    @staticmethod
    def parse_config(config):
        (port_0, port_1) = struct.unpack_from("<II",config)
        raw = list(filter(None, config[8:].split(b'\x00')))
        domains = list(set([raw[0], raw[4]]))
        ports = list(set([port_0, port_1]))
        uri = raw[1]
        image_filename = raw[3]
        return {
            'ports': ports,
            'domains': domains,
            'uri': uri,
            'image_filename': image_filename,
            'raw': raw
        }

    @Extractor.final
    def extract_config(self, p):
        if p.memory:
            offset = p.memory.find(self.pic_pattern)
            offset = self.find_payload(p.memory, offset)
            rc4_key = p.memory[offset:offset+16]
            config_size = p.memory[offset+16:offset+16+4]
            config_size = struct.unpack("<I", rc4(rc4_key, config_size))[0]
            config = rc4(rc4_key, p.memory[offset+20:offset+20+config_size])
            config = self.parse_config(config)
            return {
                'family': self.family,
                'rc4_key': hexlify(rc4_key),
                'config_size': config_size,
                'ports': config['ports'],
                'domains': config['domains'],
                'uri': config['uri'],
                'image_filename': config['image_filename'],
                'raw': config['raw']
            }
