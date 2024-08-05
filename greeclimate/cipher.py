import base64
import json
import logging
from typing import Union, Tuple

from Crypto.Cipher import AES

_logger = logging.getLogger(__name__)

class CipherBase:
    def __init__(self, key: bytes) -> None:
        self._key: bytes = key
        
    @property
    def key(self) -> str:
        return self._key.decode()
    
    @key.setter
    def key(self, value: str) -> None:
        self._key = value.encode()
        
    def encrypt(self, data) -> Tuple[str, Union[str, None]]:
        raise NotImplementedError

    def decrypt(self, data) -> dict:
        raise NotImplementedError


class CipherV1(CipherBase):
    def __init__(self, key: bytes = b'a3K8Bx%2r8Y7#xDh') -> None:
        super().__init__(key)

    def __create_cipher(self) -> AES:
        return AES.new(self._key, AES.MODE_ECB)

    def __pad(self, s) -> str:
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    def encrypt(self, data) -> Tuple[str, Union[str, None]]:
        _logger.debug("Encrypting data: %s", data)
        cipher = self.__create_cipher()
        padded = self.__pad(json.dumps(data)).encode()
        encrypted = cipher.encrypt(padded)
        encoded = base64.b64encode(encrypted).decode()
        _logger.debug("Encrypted data: %s", encoded)
        return encoded, None

    def decrypt(self, data) -> dict:
        _logger.debug("Decrypting data: %s", data)
        cipher = self.__create_cipher()
        decoded = base64.b64decode(data)
        decrypted = cipher.decrypt(decoded).decode()
        t = decrypted.replace(decrypted[decrypted.rindex('}') + 1:], '')
        _logger.debug("Decrypted data: %s", t)
        return json.loads(t)


class CipherV2(CipherBase):
    GCM_NONCE = b'\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13'
    GCM_AEAD = b'qualcomm-test'

    def __init__(self, key: bytes = b'{yxAHAY_Lm6pbC/<') -> None:
        super().__init__(key)

    def __create_cipher(self) -> AES:
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=self.GCM_NONCE)
        cipher.update(self.GCM_AEAD)
        return cipher

    def encrypt(self, data) -> Tuple[str, str]:
        _logger.debug("Encrypting data: %s", data)
        cipher = self.__create_cipher()
        encrypted, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
        encoded = base64.b64encode(encrypted).decode()
        tag = base64.b64encode(tag).decode()
        _logger.debug("Encrypted data: %s", encoded)
        _logger.debug("Cipher digest: %s", tag)
        return encoded, tag

    def decrypt(self, data) -> dict:
        _logger.info("Decrypting data: %s", data)
        cipher = self.__create_cipher()
        decoded = base64.b64decode(data)
        decrypted = cipher.decrypt(decoded).decode()
        t = decrypted.replace(decrypted[decrypted.rindex('}') + 1:], '')
        _logger.debug("Decrypted data: %s", t)
        return json.loads(t)

