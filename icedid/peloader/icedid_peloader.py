import binascii
import collections
import logging
import math
import malduck
from malduck.extractor import Extractor

log = logging.getLogger(__name__)

__author__  = "myrtus0x0"
__version__ = "1.0.1"

class IcedIDPELoader(Extractor):
    """
    IcedID PELoader Config Extractor
    """

    family = 'icedid_peloader'
    yara_rules = ('icedid_peloader',)

    @staticmethod
    def entropy(data):
        e = 0

        counter = collections.Counter(data)
        l = len(data)
        for count in counter.values():
            # count is always > 0
            p_x = count / l
            e += - p_x * math.log2(p_x)

        return e

    @staticmethod
    def strip_non_ascii(byte_str):
        res = ""
        for x in byte_str:
            if 32 < x < 128:
                res += chr(x)
        return res

    def decrypt(self, encrypted_config):
        data = encrypted_config[:-16]
        size = len(data)
        log.info("size of data: %d" % len(data))
        key = encrypted_config[-16:]
        log.info("encryption key: %s" % binascii.hexlify(key).decode("utf-8"))
        return self.internal_decrypt(data, size, key)

    def fix_key(self, key, x, y):
        tempVal = key[y:y + 4]
        tempVal = int.from_bytes(tempVal, byteorder="little")
        rotVal = (tempVal & 7) & 0xFF
        tempVal = key[x:x + 4]
        tempVal = int.from_bytes(tempVal, byteorder="little")
        tempVal = malduck.bits.ror(tempVal, rotVal, 32)
        tempVal += 1
        tempValX = tempVal.to_bytes(4, byteorder="little")
        rotVal = (tempVal & 7) & 0xFF

        tempVal = key[y:y + 4]
        tempVal = int.from_bytes(tempVal, byteorder="little")
        tempVal = malduck.bits.ror(tempVal, rotVal, 32)
        tempVal += 1
        tempValY = tempVal.to_bytes(4, byteorder="little")

        tempKey = key[:x] + tempValX + key[x + 4:]
        tempKey = tempKey[:y] + tempValY + tempKey[y + 4:]

        return tempKey

    def internal_decrypt(self, data, size, key):
        outList = []
        if size > 400:
            log.info("size of data: %d" % size)
        for i in range(size):
            x = (i & 3)
            y = ((i + 1) & 3)

            c = key[y * 4] + key[x * 4]
            c = (c ^ data[i]) & 0xFF

            outList.append(c.to_bytes(1, byteorder="little"))

            key = self.fix_key(key, x * 4, y * 4)

        return b''.join(outList)

    def parse_config(self, raw_config_blob):
        conf = {}
        config_values = raw_config_blob.split(b"\x00")
        cleaned_values = [x for x in config_values if x != b""]
        project_id = cleaned_values[0][0:4]
        loader_version = cleaned_values[0][4:8]
        cleaned_values = cleaned_values[1:-1]
        for val in cleaned_values:
            ascii_str = self.strip_non_ascii(val)
            if "/" in ascii_str:
                conf["uri"] = ascii_str
            else:
                if "domains" not in conf:
                    conf["domains"] = []
                conf["domains"].append(ascii_str)

        conf["family"] = self.family
        conf["loader_version"] = binascii.hexlify(loader_version).decode("utf-8")
        conf["project_id"] = binascii.hexlify(project_id).decode("utf-8")
        return conf

    def find_encrypted_config(self, file_data):
        window = 0x25c
        for i in range(len(file_data) - window):
            buf = file_data[i:i + window]
            entropy_val = self.entropy(buf)
            if entropy_val > 7.5 and file_data[i - 1] == 0x00 and file_data[i + window] == 0x00:
                return buf
        return None

    @Extractor.final
    def ref_c2(self, p):
        file_contents = p.readp(0, p.length)
        encrypted_config = self.find_encrypted_config(file_contents)
        if encrypted_config is None:
            log.error("unable to find encrypted buffer")
            return

        log.info("len of encrypted data: %s" % (len(encrypted_config)))
        decrypted = self.decrypt(encrypted_config)
        entropy = self.entropy(decrypted)
        log.info("decrypted data entropy: %s" % entropy)
        if entropy < 2:
            conf = self.parse_config(decrypted)
            return conf
