import logging

from malduck.extractor import Extractor
from malduck.pe import MemoryPEData

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class Caliber(Extractor):

    family     = 'caliber'
    yara_rules = ('caliber',)

    @Extractor.string
    def webhooks(self, p, addr, match):
        if p.memory:
            return {'family': 'caliber', 'webhooks': [p.utf16z(addr)]}
