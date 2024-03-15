from dataclasses import dataclass

@dataclass
class DataFrame:
    mhdr: bytes         # 1
    devAddr: bytes      # 4
    fCtrl: bytes        # 1
    fCnt: bytes         # 2
    fOpts: bytes        # variable
    fPort: bytes        # 1 (optional)
    frmPayload: bytes   # variable
    mic: bytes = b'\x00\x00\x00\x00'

    def msg_except_mic(self):
        return (self.mhdr + self.devAddr + self.fCtrl + self.fCnt +
                self.fOpts + self.fPort + self.frmPayload)

    def msg(self):
        return self.msg_except_mic() + self.mic