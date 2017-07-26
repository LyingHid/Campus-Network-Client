#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib


class EapProtocol():
    def __init__(self, config):
        self.config    = config
        self.transport = None


    # interface protocol
    def connection_made(self, transport):
        self.transport = transport
        self.start_eapol()


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

        frames['eapol']['code'          ] = b'\x02'
        frames['eapol']['md5 value'     ] = md5.digest()
        frames['eapol']['md5 extra data'] = self.config['user']['username']

        self.transport.send_data(frames)

        print('response md5 challenge')


    def response_success(self, frames):
        print('nice')


    def response_failure(self, frames):
        print('oh no')
