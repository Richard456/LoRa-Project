import math
import os

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from collections import deque

from ..lorawan_packets.join_accept import JoinAccept

@dataclass
class DeviceInfo:
    appEUI: bytes
    devEUI: bytes
    appKey: bytes

class DeviceInfoDB:
    def __init__(self):
        self.db = {}

    def add_device(self, device):
        self.db[(device.appEUI, device.devEUI)] = device

    def get_device_info(self, appEUI, devEUI):
        if (appEUI, devEUI) not in self.db:
            return None
        else:
            return self.db[(appEUI, devEUI)]

class DeviceSession:
    def __init__(self, appKey, devNonce, appNonce, netID, devAddr):
        self.devNonce = devNonce
        self.appNonce = appNonce
        self.devAddr = devAddr
        self.netID = netID
        self.appKey = appKey
        self.fCntDown = 0
        self.last_fCntUp = -1

        self.last_fragid = -1
        self.next_pos = 0
        self.frag_buffer = []

        pad16 = b'\x00' * 7
        tail = appNonce + netID + devNonce + pad16
        cipher = AES.new(appKey, AES.MODE_ECB)

        self.nwkSKey = cipher.encrypt(b'\x01' + tail)
        self.appSKey = cipher.encrypt(b'\x02' + tail)
        self.nwk_cipher = AES.new(self.nwkSKey, AES.MODE_ECB)
        self.app_cipher = AES.new(self.appSKey, AES.MODE_ECB)

        # batched ack
        self.batchAckRequested = False
        self.ackCounter = 0

        self.feedback_buffer = deque(maxlen=8)
        self.fcnt_mark = -1

        print(f'NwkSKey {self.nwkSKey.hex()}, AppSKey {self.appSKey.hex()}')

    # Note: fcnt is 4 byte long
    def crypt(self, fport, is_dl, fcnt, src):
        c = self.nwk_cipher if fport == 0 else self.app_cipher
        dir = b'\x01' if is_dl else b'\x00'
        blocks = math.ceil(len(src) / 16)
        skey = b''.join([c.encrypt(b'\x01\x00\x00\x00\x00' + dir +
                         self.devAddr + fcnt + b'\x00' + i.to_bytes(1, 'little'))
                         for i in range(1, blocks+1)])
        return bytes(a ^ b for a, b in zip(src, skey))

    def mic(self, is_dl, fcnt, msg):
        dir = b'\x01' if is_dl else b'\x00'
        b0 = b'\x49\x00\x00\x00\x00' + dir + self.devAddr + fcnt + b'\x00' + len(msg).to_bytes(1, 'little')

        cobj = CMAC.new(self.nwkSKey, ciphermod=AES)
        cobj.update(b0 + msg)
        digest = cobj.digest()
        return digest[0:4]

    def get_full_fcnt_up(self, fCnt_short: bytes) -> int:
        fcnt_lower = int.from_bytes(fCnt_short, 'little')
        last_upper = 0 if self.last_fCntUp < 0 else (self.last_fCntUp >> 16) & 0xFFFF

        test_range = [-2, -1, 0, 1, 2]
        candidates = [((x + last_upper) << 16) + fcnt_lower for x in test_range]
        # filter out negative items to prevent overflow exception
        diff = [x - self.last_fCntUp for x in candidates if x > self.last_fCntUp]

        return min(diff) + self.last_fCntUp

    def update_fcnt_up(self, fcnt: int):
        self.last_fCntUp = fcnt

    def generate_join_accept_msg(self):
        mhdr = b'\x20' # Mtype: 001, RFU: 000, Major: 00

        # TODO: Make the following paremeters configurable
        # Using Rate 10 (SF10BW500) for Rx2 Window
        dlSettings = b'\x0a'
        # rx1 delay = 1 second
        rxDelay = b'\x01'

        join_acc = JoinAccept(mhdr, self.appNonce, self.netID, self.devAddr,
                              dlSettings, rxDelay)
        join_acc.add_mic(self.appKey)

        return join_acc.encrypted(self.appKey)

class SessionManager:
    def __init__(self, device_db, netID = b'\x32\x05\x00'):
        self.device_db = device_db
        self.netID = netID
        self.next_addr = SessionManager._random_bare_addr()
        # devAddr -> (DeviceInfo, DeviceSession)
        self.sessions = {}

    def create_session(self, join_req):
        dev_info = self.device_db.get_device_info(join_req.appEUI, join_req.devEUI)
        if dev_info is None:
            print(f'Device not found in DB')
            return None

        if not join_req.verify_mic(dev_info.appKey):
            print('Join request MIC verification failure')
            return None

        # Clean up previous session if it exists
        prev_addr = self.device_address(join_req.appEUI, join_req.devEUI)
        if prev_addr is not None:
            del self.sessions[prev_addr]

        appNonce = os.urandom(3)
        new_addr = self.create_new_addr()
        new_addr_bytes = new_addr.to_bytes(4, 'little')
        print(f'New addr {new_addr_bytes.hex()}')

        session = DeviceSession(dev_info.appKey, join_req.devNonce, appNonce,
                                self.netID, new_addr_bytes)
        self.sessions[new_addr] = (dev_info, session)

        return session

    def find_session(self, dev_addr):
        if isinstance(dev_addr, bytes):
            dev_addr = int.from_bytes(dev_addr, 'little')
        return self.sessions[dev_addr] if dev_addr in self.sessions else None

    def device_address(self, appEUI, devEUI):
        for addr, (info, _) in self.sessions.items():
            if info.appEUI == appEUI and info.devEUI == devEUI:
                return addr
        return None

    def _random_bare_addr():
        return int.from_bytes(os.urandom(4), 'little') & 0x01FFFFFF

    def _make_dev_addr(self, bare_addr):
        n7 = self.netID[2] & 0xFE
        dev_addr = (n7 << 25) | (bare_addr & 0x01FFFFFF)
        return dev_addr

    def create_new_addr(self):
        new_addr = self._make_dev_addr(self.next_addr)

        # Try 100 times to get a new addr in case of collision
        for i in range(100):
            if new_addr not in self.sessions:
                print(f'addr {new_addr} success')
                break
            else:
                print(f'addr {new_addr} fail, retrying')
                self.next_addr = SessionManager._random_bare_addr()
                new_addr = self._make_dev_addr(self.next_addr)

        if new_addr in self.sessions:
            return None

        self.next_addr = (self.next_addr + 1) & 0x01FFFFFF
        return new_addr
