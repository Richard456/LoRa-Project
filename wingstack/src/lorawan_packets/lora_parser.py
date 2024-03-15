from enum import Enum

from .data_frame import DataFrame
from .join_request import JoinRequest

class LoRaWANType(Enum):
    JOIN_REQUEST = 0
    JOIN_ACCEPT = 1
    UNCONFIRMED_UP = 2
    UNCONFIMRED_DOWN = 3
    CONFIRMED_UP = 4
    CONFIRMED_DOWN = 5
    RFU = 6
    PROPRIETARY = 7

def parse_packet(payload: bytes):
    mhdr = payload[0]
    pkt_type = (mhdr >> 5) & 7

    if pkt_type == LoRaWANType.JOIN_REQUEST.value:
        return parse_join_request(payload)
    if pkt_type in [LoRaWANType.UNCONFIRMED_UP.value,
                    LoRaWANType.UNCONFIMRED_DOWN.value,
                    LoRaWANType.CONFIRMED_UP.value,
                    LoRaWANType.CONFIRMED_DOWN.value]:
        return parse_data_frame(payload)
    else:
        # TODO: Support other types
        return None

def parse_join_request(payload: bytes):
    if len(payload) != 23:
        return None

    return JoinRequest(payload[0:1], payload[1:9], payload[9:17], payload[17:19], payload[19:])

def parse_data_frame(payload: bytes):
    if len(payload) < 13:
        return None

    mhdr = payload[0:1]
    devAddr = payload[1:5]
    fCtrl = payload[5:6]
    fCnt = payload[6:8]

    fopts_length = payload[5] & 0xF
    fopts_end = 8 + fopts_length
    fOpts = payload[8:fopts_end]
    fPort = payload[fopts_end:fopts_end+1]
    frmPayload = payload[fopts_end+1:-4]
    mic = payload[-4:]

    return DataFrame(mhdr, devAddr, fCtrl, fCnt, fOpts, fPort, frmPayload, mic)