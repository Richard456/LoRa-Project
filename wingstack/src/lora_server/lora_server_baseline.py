import argparse
import base64
from collections import deque
import datetime
import json
import os
import signal
import socket
import sys
from enum import Enum
from queue import SimpleQueue

from .config import Config
from .webhook_worker import WebhookWorker
from .session_manager import DeviceInfo, DeviceInfoDB, DeviceSession, SessionManager
from ..lorawan_packets import lora_parser
from ..lorawan_packets.data_frame import DataFrame
from ..lorawan_packets.join_request import JoinRequest
from ..lorawan_packets.join_accept import JoinAccept

DL_QUEUES={}
PULL_GWS={}
CONFIG=Config()
SESSION_MGR=None
WEBHOOK=None

# store the packets in a buffer
BUFFER_SIZE = 100
PACKET_BUFFER = deque(maxlen=BUFFER_SIZE)

class GatewayCmd(Enum):
    PUSH_DATA = 0
    PUSH_ACK = 1
    PULL_DATA = 2
    PULL_RESP = 3
    PULL_ACK = 4
    TX_ACK = 5

def gen_dl(gw_id, rxpk_obj, rate, delay, payload):
    dl_freq = 923.3 + (rxpk_obj['chan'] & 7) * 0.6
    dl_object = {
        'txpk': {
            'imme': False,
            'tmst': rxpk_obj['tmst'] + delay,
            'freq': dl_freq,
            'rfch': 0,
            'powe': 26,
            'modu': 'LORA',
            'datr': rate,
            'codr': '4/5',
            'ipol': True,
            'size': len(payload),
            'ncrc': True,
            'data': base64.b64encode(payload).decode('utf-8'),
        },
    }

    if gw_id not in DL_QUEUES:
        DL_QUEUES[gw_id] = SimpleQueue()

    DL_QUEUES[gw_id].put(dl_object)

def handle_join_request(gw_id, join_req, rxpk_obj):
    print(f'Join Request: AppEUI {join_req.appEUI.hex()} DevEUI {join_req.devEUI.hex()}')

    session = SESSION_MGR.create_session(join_req)
    if session is not None:
        dl_payload = session.generate_join_accept_msg()
        gen_dl(gw_id, rxpk_obj, 'SF10BW500', 5000000, dl_payload)

def make_webhook(rxpk_obj, dev_info, data_frame, data_payload):
    webhook_obj = {
        'end_device_ids': {
            # device_id field
            # application_ids/application_id
            'dev_eui': bytes(reversed(dev_info.devEUI)).hex(),
            'join_eui': bytes(reversed(dev_info.appEUI)).hex(),
            'dev_addr': bytes(reversed(data_frame.devAddr)).hex(),
        },
        'uplink_message': {
            # TODO: f_cnt convert to 32-bits
            'f_cnt': int.from_bytes(data_frame.fCnt, 'little'),
            'f_port': int.from_bytes(data_frame.fPort, 'little'),
            'frm_payload': base64.b64encode(data_payload).decode('utf-8')
        },
        'received_at': datetime.datetime.now().isoformat()
    }

    WEBHOOK.webhook(webhook_obj)

def is_frag_data(data_frame):
    return len(data_frame.fOpts) >= 4 and data_frame.fOpts[0] == 0x91

def handle_frag_data(session, data_frame, data_plain):
    if len(data_frame.fOpts) < 4:
        return None

    flag_id1 = data_frame.fOpts[1]
    id2 = data_frame.fOpts[2]
    offset = data_frame.fOpts[3]

    more_frags = (flag_id1 >> 7) & 1
    frag_id = (flag_id1 & 0xF) * 256 + id2

    if offset == 0:
        session.last_fragid = frag_id
        session.next_pos = len(data_plain)
        session.frag_buffer = data_plain
    else:
        # TODO: support overlapping
        if frag_id == session.last_fragid and offset == session.next_pos:
            session.frag_buffer = session.frag_buffer + data_plain
            session.next_pos = session.next_pos + len(data_plain)
        else:
            return None

    if not more_frags:
        return session.frag_buffer

    return None

def handle_data_up(gw_id, data_frame, rxpk_obj):
    print(f'Data Up: DevAddr {data_frame.devAddr.hex()}, fCnt {int.from_bytes(data_frame.fCnt, "little")}')

    find_result = SESSION_MGR.find_session(data_frame.devAddr)
    if find_result is None:
        print(f'Session not found for address {data_frame.devAddr.hex()}')
        return

    print(f'First 32 bytes of encrypted FrmPayload: {data_frame.frmPayload[0:32].hex()}')

    dev_info, session = find_result

    fcnt_full_int = session.get_full_fcnt_up(data_frame.fCnt)
    fcnt_full = fcnt_full_int.to_bytes(4, 'little')
    data_plain = session.crypt(data_frame.fPort, False, fcnt_full, data_frame.frmPayload)

    mic_calc = session.mic(False, fcnt_full, data_frame.msg_except_mic())
    if mic_calc == data_frame.mic:
        print('MIC validation passed')
        fcntdl_full = session.fCntDown.to_bytes(4, 'little')
        ack = DataFrame(b'\x60', data_frame.devAddr, b'\x20', fcntdl_full[0:2], b'', b'', b'')
        ack.mic = session.mic(True, fcntdl_full, ack.msg_except_mic())
        dl_rate = rxpk_obj['datr'][:-3] + '500'
        gen_dl(gw_id, rxpk_obj, dl_rate, 1000000, ack.msg())
        session.fCntDown = session.fCntDown + 1
        session.update_fcnt_up(fcnt_full_int)

        if is_frag_data(data_frame):
            assembled = handle_frag_data(session, data_frame, data_plain)
            if assembled is not None:
                make_webhook(rxpk_obj, dev_info, data_frame, assembled)
        else:
            make_webhook(rxpk_obj, dev_info, data_frame, data_plain)

    print(f'First 32 bytes of plain FrmPayload: {data_plain[0:32].hex()}')

def _detect_duplicate_packet(packet):
    print('Checking duplicate packet...')
    packet_key = (packet.devAddr, packet.fCnt)
    # Check if this packet has already been received
    if packet_key in PACKET_BUFFER:
        print(f'Duplicate packet received, discarding...')
        return True
    
    # add into the buffer, with the value as current time in milliseconds
    PACKET_BUFFER.append(packet_key)
    return False

def handle_push_data(socket, gw_addr, token, gw_id, push_obj):
    print(f'PUSH_DATA from gateway {gw_id.hex()}')

    if 'rxpk' in push_obj:
        for rxpk in push_obj['rxpk']:
            if 'data' not in rxpk:
                continue

            # Only filter CRC failure on gateways that report CRC
            if 'crc_match' in rxpk and rxpk['crc_match'] != 1:
                continue

            decoded_data = base64.b64decode(rxpk['data'])

            # Sometimes gateway report empty data for unknown reason, skip it
            if len(decoded_data) < 1:
                continue

            packet_type = lora_parser.LoRaWANType((decoded_data[0] >> 5) & 7)
            print(f'UP Packet type: {packet_type.name}')

            packet_parsed = lora_parser.parse_packet(decoded_data)
            if packet_parsed is not None:
                if isinstance(packet_parsed, JoinRequest):
                    handle_join_request(gw_id, packet_parsed, rxpk)
                if isinstance(packet_parsed, DataFrame):
                    is_duplicate = _detect_duplicate_packet(packet_parsed)
                    if is_duplicate:
                        continue
                    handle_data_up(gw_id, packet_parsed, rxpk)

    push_ack = b'\x02' + token + b'\x01'
    socket.sendto(push_ack, gw_addr)

def check_pull(serv_sock, gw_id):
    if gw_id in PULL_GWS:
        if gw_id in DL_QUEUES and not DL_QUEUES[gw_id].empty():
            dl_object = DL_QUEUES[gw_id].get()
            gw_addr, token = PULL_GWS[gw_id]
            dl_data = b'\x02' + token + b'\x03' + json.dumps(dl_object).encode('utf-8')
            serv_sock.sendto(dl_data, gw_addr)
            # del PULL_GWS[gw_id]

def sigint_handler(sig, frame):
    print('SIGINT captured, shutting down...')
    if WEBHOOK is not None:
        WEBHOOK.terminate()

    sys.exit(0)

def main():
    CONFIG.parse_args()
    signal.signal(signal.SIGINT, sigint_handler)
    device_db = DeviceInfoDB()
    devices = CONFIG.devices
    for _, device_info in devices.items():
        device = DeviceInfo(device_info['appEUI'], device_info['devEUI'], device_info['appKey'])
        device_db.add_device(device)

    global SESSION_MGR
    SESSION_MGR = SessionManager(device_db)

    global WEBHOOK
    WEBHOOK = WebhookWorker(CONFIG.webhooks)

    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serv_sock.bind((CONFIG.bind, CONFIG.port))

    while True:
        payload, gw_addr = serv_sock.recvfrom(4096)
        print(f'RCV {len(payload)}: {payload[0:4].hex()}')

        if len(payload) < 12:
            print('UP: Packet too short')
            continue

        if payload[0] != 2:
            print('UP: Incorrect protocol version')
            continue

        token = payload[1:3]
        gw_id = payload[4:12]
        try:
            json_obj = json.loads(payload[12:].decode('utf-8'))
        except:
            json_obj = None if len(payload) > 12 else []
        finally:
            if payload[3] == GatewayCmd.PUSH_DATA.value:
                print('PUSH_DATA')
                if (json_obj is not None):
                    handle_push_data(serv_sock, gw_addr, token, gw_id, json_obj)
                    check_pull(serv_sock, gw_id)

            if payload[3] == GatewayCmd.PULL_DATA.value:
                print(f'PULL_DATA from gateway {gw_id.hex()}')
                pull_ack = b'\x02' + token + b'\x04'
                serv_sock.sendto(pull_ack, gw_addr)
                PULL_GWS[gw_id] = (gw_addr, token)
                check_pull(serv_sock, gw_id)

if __name__ == '__main__':
    main()
