import logging
import base64
from malduck.extractor import Extractor
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class ASyncRAT(Extractor):

    """
    ASyncRAT Configuration Extractor
    """

    family              = 'asyncrat'
    yara_rules          = ('asyncrat',)

    AES_BLOCK_SIZE  = 128
    AES_KEY_SIZE    = 256
    AES_CIPHER_MODE = AES.MODE_CBC

    @staticmethod
    def get_salt():
        return bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")

    def decrypt(self, key, ciphertext):
        aes_key = PBKDF2(key, self.get_salt(), 32, 50000)
        cipher = AES.new(aes_key, self.AES_CIPHER_MODE, ciphertext[32:32+16])
        plaintext = cipher.decrypt(ciphertext[48:]).decode('ascii', 'ignore').strip()
        return plaintext

    @staticmethod
    def get_string(data, index):
        return data[index][1:].decode('utf-8', 'ignore')

    def decrypt_config_item(self, key, data, index):
        try:
            data = base64.b64decode(self.get_string(data, index))
            plaintext = self.decrypt(key, data)
            if plaintext.lower() == 'true':
                return True
            if plaintext.lower() == 'false':
                return False
            return plaintext
        except Exception as error:
            log.error(error)
            return ''

    @staticmethod
    def get_wide_string(data, index):
        data = data[index][1:] + b'\x00'
        return data.decode('utf-16')

    @Extractor.extractor('magic_cslr_0')
    def asyncrat(self, p, addr):
        strings_offset = p.uint32v(addr+0x40)
        strings_size = p.uint32v(addr+0x44)
        data = p.readv(addr+strings_offset, strings_size)
        data = data.split(b'\x00\x00')
        key = base64.b64decode(self.get_string(data, 7))
        log.debug('extracted key: ' + str(key))
        config = {
            'family': self.family,
            'host': self.decrypt_config_item(key, data, 2),
            'port': self.decrypt_config_item(key, data, 1),
            'version': self.decrypt_config_item(key, data, 3),
            'install_folder': self.get_wide_string(data, 5),
            'install_file': self.get_wide_string(data, 6),
            'install': self.decrypt_config_item(key, data, 4),
            'mutex': self.decrypt_config_item(key, data, 8),
            'pastebin': self.decrypt_config_item(key, data, 12)
        }
        return config
