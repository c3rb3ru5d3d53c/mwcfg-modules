import logging

from malduck.extractor import Extractor
from malduck.pe import PE
from malduck import asciiz
import clr
import dnfile
import dotnetfile

log = logging.getLogger(__name__)

__author__  = "@c3rb3ru5d3d53c"
__version__ = "1.0.0"

class Redline(Extractor):
    """
    Redline Stealer Config Extractor
    """

    family     = 'redline'
    yara_rules = ('redline',)

    @Extractor.final
    def string_0(self, p):
        return {
            'family': self.family,
            'hosts': ['placeholder']
        }
