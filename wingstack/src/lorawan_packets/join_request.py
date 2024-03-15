from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from dataclasses import dataclass

@dataclass
class JoinRequest:
    mhdr: bytes
    appEUI: bytes
    devEUI: bytes
    devNonce: bytes
    mic: bytes = b'\x00\x00\x00\x00'

    def _compute_mic(self, appKey: bytes) -> bytes:
        payload = self.mhdr + self.appEUI + self.devEUI + self.devNonce
        cobj = CMAC.new(appKey, ciphermod=AES)
        cobj.update(payload)
        digest = cobj.digest()
        return digest[0:4]

    def add_mic(self, appKey: bytes):
        self.mic = self._compute_mic(appKey)

    def verify_mic(self, appKey: bytes) -> bool:
        return self.mic == self._compute_mic(appKey)