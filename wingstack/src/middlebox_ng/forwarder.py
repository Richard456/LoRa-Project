import argparse
import asyncio
import base64
import json
import socket
import sys
import signal

from queue import SimpleQueue

from ..lorawan_packets import lora_parser 
from ..lorawan_packets.join_request import JoinRequest

SERV_IP = '127.0.0.1'
SERV_PORT = 1700
CLOUD_IP = '0.0.0.0'
CLOUD_PORT = 1700

SHUTDOWN = None
def sigint_handler(sig, frame):
    print('SIGINT captured, shutting down...')
    if SHUTDOWN is None:
        sys.exit(0)
    else:
        SHUTDOWN.set_result(True)

class CloudSideProtocol:
    def __init__(self, loop, gw_ep, client_addr):
        self.gw_ep = gw_ep
        self.client_addr = client_addr
        self.transport = None
        self.loop = loop
        self.q = SimpleQueue()
    
    def connection_made(self, transport):
        self.transport = transport
        self.dispatch_message()

    def dispatch_message(self):
        if self.transport != None:
            while not self.q.empty():
                msg = self.q.get()
                self.transport.sendto(msg)

    def forward_msg(self, msg):
        self.q.put(msg)
        self.dispatch_message()

    def datagram_received(self, data, addr):
        self.gw_ep.transport.sendto(data, self.client_addr)

    def connection_lost(self, exc):
        pass

class GWSideProtocol:
    def __init__(self, loop):
        self.admap = {}
        self.loop = loop
    
    def connection_made(self, transport):
        self.transport = transport

    # Handles 
    async def datagram_received_async(self, data, addr):
        print('DGRAM RECV')
        h = self.admap.get(addr)
        if h == None:
            _, h = await(self.loop.create_datagram_endpoint(
                lambda: CloudSideProtocol(self.loop, self, addr),
                remote_addr = (CLOUD_IP, CLOUD_PORT)
            ))
            self.admap[addr] = h

        examine_ul(data)
        h.forward_msg(data)

    def datagram_received(self, data, addr):
        self.loop.create_task(self.datagram_received_async(data, addr))

    def connection_lost(self, exc):
        pass

async def main():
    loop = asyncio.get_running_loop()
    SHUTDOWN = loop.create_future()

    gw_transport, _ = await loop.create_datagram_endpoint(
        lambda: GWSideProtocol(loop),
        local_addr = (SERV_IP, SERV_PORT)
    )

    try:
        await SHUTDOWN
    finally:
        gw_transport.close()

def examine_ul(msg: bytes):
    start_position = msg.find(b'{')
    json_payload = msg[start_position:]

    try:
        strt = json_payload.decode('utf-8')
        print(f'strt {strt}')
        json_obj = json.loads(json_payload.decode('utf-8'))
        if 'rxpk' not in json_obj:
            print('UP does not have rxpk')
            return

        for rxpk in json_obj['rxpk']:
            if 'data' not in rxpk or rxpk['crc_match'] != 1:
                print('lack of data or corrupted')
                continue

            decoded_data = base64.b64decode(rxpk['data'])
            packet_type = lora_parser.LoRaWANType((decoded_data[0] >> 5) & 7)
            print(f'UP Packet type: {packet_type.name}')

            packet_parsed = lora_parser.parse_packet(decoded_data)
            if packet_parsed is not None and isinstance(packet_parsed, JoinRequest):
                print(f'Join Request: AppEUI {packet_parsed.hex()}')
    except Exception as e:
        print(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog="socket_forwarder.py",
        description="A simple sniffer on port specified",
        epilog="^_^",
    )

    parser.add_argument(
        "-lp",
        "--local-port",
        dest="dst_port",
        action="store",
        default=1700,
        help="Port this middle box is listening to",
    )

    parser.add_argument(
        "-la",
        "--local-address",
        dest="dst_ip",
        action="store",
        default="127.0.0.1",
        help="IP address of this middle box.",
    )

    parser.add_argument(
        "-ca",
        "--cloud-address",
        dest="cld_domain",
        action="store",
        default="symrec.nam1.cloud.thethings.industries",
        help="IP address of this middle box.",
    )

    parser.add_argument(
        "-cp",
        "--cloud-port",
        dest="cld_port",
        action="store",
        type=int,
        default=1700,
        help="Port this middle box will forward to",
    )

    signal.signal(signal.SIGINT, sigint_handler)

    args = parser.parse_args()
    UDP_IP = args.dst_ip
    UDP_PORT = args.dst_port

    CLOUD_IP = socket.gethostbyname(args.cld_domain)
    CLOUD_PORT = args.cld_port

    asyncio.run(main())