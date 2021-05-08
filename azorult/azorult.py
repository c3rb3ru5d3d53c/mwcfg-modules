import logging

from malduck.extractor import Extractor
from malduck.pe import MemoryPEData

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class Azorult(Extractor):

    """
    Azorult C2 Domain Configuration Extractor
    """

    family     = 'azorult'
    yara_rules = 'azorult',

    @Extractor.extractor('ref_c2')
    def ref_c2(self, p, addr):
        c2_list_va = p.uint32v(addr + 21)
        c2 = p.asciiz(c2_list_va).decode('utf-8')
        if len(c2) <= 0:
            return None
        return {'family': 'azorult', 'urls': [c2]}
