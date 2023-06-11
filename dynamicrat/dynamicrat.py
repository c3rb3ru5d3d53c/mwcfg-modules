
import re
import logging
from io import BytesIO
from zipfile import ZipFile
from hexdump import hexdump
from malduck import md5, aes
from dataclasses import dataclass
from malduck.extractor import extractor
from malduck import Extractor
from base64 import b64encode

log = logging.getLogger(__name__)

__author__ = "@AnFam17 (RussianPanda)"
__version__ = "1.0.0"

@dataclass
class Config():
    hosts: list = None
    raw: str = None

class DynamicRAT(Extractor):

    """
    DynamicRAT Configuration Extractor
    """

    family = "dynamicrat"
    yara_rules = ("dynamicrat",)

    r_key = re.compile(rb"assets\.dat.{8}([A-Za-z0-9!@#$%^&*()-_=+{}\[\]|:;'<>,./?]+)")

    @staticmethod
    def get_zip_file(data, class_file):
        with ZipFile(BytesIO(data), 'r') as jar:
            try:
                return jar.read(class_file)
            except KeyError:
                    return None

    def get_key(self, data):
        match = self.r_key.search(data)
        if match is None: return None
        return md5(match.group(1).decode('utf-8').encode())

    @staticmethod
    def get_hosts(data):
        return data.split(b'\x00\x00\x00\x01')[1][2:].split(b'_')[0].decode('ascii')

    @Extractor.final
    def get_config(self, p):
        try:
            cfg = Config()
            data = p.opened_file.read()
            cfg.key = self.get_key(self.get_zip_file(data, class_file='dynamic/client/Main.class'))
            assert cfg.key is not None
            ct = self.get_zip_file(data, class_file='assets.dat')[4:]
            cfg.raw = aes.ecb.decrypt(cfg.key, ct)
            assert cfg.raw is not None
            cfg.hosts = [self.get_hosts(cfg.raw)]
            assert cfg.hosts is not None
            return {
                'family': 'dynamicrat',
                'hosts': cfg.hosts,
                'raw': b64encode(cfg.raw)
            }

        except Exception as error:
            log.warning(error)
            return None
