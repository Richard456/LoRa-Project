from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from dataclasses import dataclass

@dataclass
class JoinAccept:
    mhdr: bytes
    appNonce: bytes
    netID: bytes
    devAddr: bytes
    dlSettings: bytes
    rxDelay: bytes
    cfList: bytes = b''
    mic: bytes = b'\x00\x00\x00\x00'

    def _compute_mic(self, appKey: bytes) -> bytes:
        payload = self.mhdr + self.appNonce + self.netID + self.devAddr + self.dlSettings + self.rxDelay
        if self.cfList is not None:
            payload = payload + self.cfList

        cobj = CMAC.new(appKey, ciphermod=AES)
        cobj.update(payload)
        digest = cobj.digest()
        return digest[0:4]

    def add_mic(self, appKey: bytes):
        self.mic = self._compute_mic(appKey)

    def encrypted(self, appKey: bytes) -> bytes:
        plain = self.appNonce + self.netID + self.devAddr + self.dlSettings + self.rxDelay
        if self.cfList is not None:
            plain = plain + self.cfList
        plain = plain + self.mic

        # https://www.thethingsnetwork.org/docs/lorawan/the-things-certified-security/
        # JoinAccept uses ECB mode
        cipher = AES.new(appKey, AES.MODE_ECB)

        # JoinAccept uses *decrypt* for encryption
        body = cipher.decrypt(plain)
        return self.mhdr + body
