import argparse
import json
import sys

from os.path import expanduser

class Config:
    default_config_locations = [
        expanduser('~/.config/wingstack/server_config.json'),
        '/etc/wingstack/server_config.json',
    ]

    def __init__(self):
        self.bind = '0.0.0.0'
        self.port = 1700
        self.webhooks = []
        self.devices = {}

    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog='lora_server.py',
            description='LoRa Server of WingStack',
        )

        parser.add_argument(
            '-b',
            '--bind',
            action='store',
            dest='bind',
            help='The IP address for the server to bind'
        )

        parser.add_argument(
            '-p',
            '--port',
            action='store',
            dest='port',
            help='The port of the server'
        )

        parser.add_argument(
            '-c',
            '--config',
            action='store',
            dest='config',
            help='The location of configuration file'
        )

        args = parser.parse_args()

        self.parse_config_file(args.config)

        if args.bind is not None:
            self.bind = args.bind

        if args.port is not None:
            self.port = args.port

    def parse_config_file(self, filename):
        fh = None

        if filename is not None:
            try:
                fh = open(filename, 'r')
            except Exception as e:
                print(f'Failed to open config file {filename}: {e}')
                sys.exit(1)
        else:
            for p in Config.default_config_locations:
                try:
                    fh = open(p, 'r')
                    break
                except Exception as e:
                    print(f"Opening default config location '{p}' failed: {e}")
                    continue
            if fh is None:
                print('Failed to open all config locations')
                sys.exit(1)

        try:
            config_obj = json.load(fh)
        except Exception as e:
            print(f'Failed parsing config JSON: {e}')
            sys.exit(1)

        if 'server' not in config_obj:
            print('Config file missing server section')
            sys.exit(1)
        self.process_server_config(config_obj['server'])

        if 'devices' not in config_obj:
            print('Config file missing devices section')
            sys.exit(1)
        self.process_device_config(config_obj['devices'])

    def process_server_config(self, server_obj):
        if 'bind' not in server_obj:
            print('Server ip not specified in config file')
            sys.exit(1)
        self.bind = server_obj['bind']

        if 'port' not in server_obj:
            print('Port not specified in config file')
            sys.exit(1)
        self.port = server_obj['port']

        if 'webhooks' in server_obj:
            if (isinstance(server_obj['webhooks'], list) and
                all(isinstance(elem, str) for elem in server_obj['webhooks'])):
                self.webhooks = server_obj['webhooks']
            else:
                print('Webhook should be a list of strings')
                sys.exit(1)

    def process_device_config(self, devices_obj):
        for device_id, device_info in devices_obj.items():
            if all(k in device_info for k in ("appEUI", "devEUI", "appKey")):
                try:
                    self.devices[device_id] = {
                        'appEUI': bytes.fromhex(device_info['appEUI']),
                        'devEUI': bytes.fromhex(device_info['devEUI']),
                        'appKey': bytes.fromhex(device_info['appKey'])
                    }
                except ValueError:
                    print(f'Invalid hexadecimal value in device information for {device_id}')
                    sys.exit(1)
            else:
                print(f'Missing device information for {device_id}. appEUI, devEUI, and appkey should all be specified.')
                sys.exit(1)
