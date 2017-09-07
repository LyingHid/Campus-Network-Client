#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib

from packets import standard
from packets import ruijie


class EapProtocol():
    def __init__(self, config):
        self.config = config
        self.transport = None

        config['packet']['parsers']['ether'].insert(0, standard.ether_parser)
        config['packet']['parsers']['8021x'].insert(0, standard.x8021_parser)
        config['packet']['parsers']['eapol'].insert(0, standard.eapol_parser)

        config['packet']['builders']['ether'].insert(0, standard.ether_builder)
        config['packet']['builders']['8021x'].insert(0, standard.x8021_builder)
        config['packet']['builders']['eapol'].insert(0, standard.eapol_builder)


    # interface protocol
    def connection_made(self, transport):
        self.transport = transport
        self.start_eapol()


    # interface protocol
    def connection_lost(self, reason):
        pass


    # interface protocol
    def data_received(self, frames):
        if frames['eapol']['code'] == b'\x01':
            if frames['eapol']['type'] == b'\x01':
                self.response_id(frames)
            else:  # frames['eapol']['type'] == b'\x04':
                self.response_md5_challenge(frames)
        elif frames['eapol']['code'] == b'\x03':
            self.response_success(frames)
        elif frames['eapol']['code'] == b'\x04':
            self.response_failure(frames)


    def start_eapol(self):
        frames = {}

        frames['raw'] = {}

        frames['ether'] = {}
        frames['ether']['destination'] = b'\x01\xd0\xf8\x00\x00\x03'
        frames['ether']['source'     ] = self.transport.get_address()
        frames['ether']['protocol'   ] = b'\x88\x8E'

        frames['8021x'] = {}
        frames['8021x']['version'] = b'\x01'
        frames['8021x']['type'   ] = b'\x01'
        frames['8021x']['length' ] = b'\x0000'

        self.transport.send_data(frames)

        print('start eapol')


    def response_id(self, frames):
        src_mac = frames['ether']['source'     ]
        dst_mac = frames['ether']['destination']
        frames['ether']['source'     ] = dst_mac
        frames['ether']['destination'] = src_mac

        frames['eapol']['code'    ] = b'\x02'
        frames['eapol']['identity'] = self.config['user']['username']

        self.transport.send_data(frames)

        print('response identity')


    def response_md5_challenge(self, frames):
        md5 = hashlib.md5()
        md5.update(frames['eapol']['id'])
        md5.update(self.config['user']['password'])
        md5.update(frames['eapol']['md5 value'])

        src_mac = frames['ether']['source'     ]
        dst_mac = frames['ether']['destination']
        frames['ether']['source'     ] = dst_mac
        frames['ether']['destination'] = src_mac

        frames['eapol']['code'] = b'\x02'
        frames['eapol']['md5 value'] = md5.digest()
        if 'md5 extra data' in frames['eapol']:
            frames['eapol']['md5 extra data'] = self.config['user']['username']

        self.transport.send_data(frames)

        print('response md5 challenge')


    def response_success(self, frames):
        print('authentication successed')
        self.transport.lose_connection()


    def response_failure(self, frames):
        print('authentication failed')
        self.transport.lose_connection()


class RuijieProtocol(EapProtocol):
    def __init__(self, config):
        EapProtocol.__init__(self, config)

        self.round = 0

        config['packet']['parsers']['eapol'].append(ruijie.eapol_parser)
        config['packet']['builders']['ether'].append(ruijie.ether_builder)


    def connection_made(self, transport):
        self.round = 1

        EapProtocol.connection_made(self, transport)


    def response_md5_challenge(self, frames):
        frames['eapol']['md5 extra data'] = self.config['user']['username']
        frames['ruijie']['username'] = self.config['user']['username']
        frames['ruijie']['password'] = self.config['user']['password']

        EapProtocol.response_md5_challenge(self, frames)


    def response_success(self, frames):
        if self.round <= 1:
            self.round += 1
            # TODO: dhcp and ip info
            self.start_eapol()
        else:
            EapProtocol.response_success(self, frames)

            print('notice')
            print(frames['ruijie']['notice'].decode('gbk').replace('\r\n', '\n').strip())
            if 'bill' in frames['ruijie']:
                print('bill')
                print(frames['ruijie']['bill'].decode('gbk').strip())


    def response_failure(self, frames):
        EapProtocol.response_failure(self, frames)

        print('notice')
        print(frames['ruijie']['notice'].decode('gbk').replace('\r\n', '\n').strip())


def get_default(config):
    """ protocol factory
    the factory can be extended to support other schools
    """
    return RuijieProtocol(config)
