#!/usr/bin/python
# -*- coding: utf-8 -*-


class EapProtocol():
    def __init__(self, config):
        self.config    = config
        self.transport = None


    # interface protocol
    def connection_made(self, transport):
        self.transport = transport
        self.start_eapol()


    # interface protocol
    def data_received(self, frames): pass


    def start_eapol(self):
        frames = {}

        frames['raw'] = {}
        frames['top'] = 'ether'
        frames['bottom'] = '8021x'

        frames['ether'] = {}
        frames['ether']['destination'] = b'\x01\xd0\xf8\x00\x00\x03'
        frames['ether']['source']      = self.transport.get_address()
        frames['ether']['protocol']    = b'\x88\x8E'

        frames['8021x'] = {}
        frames['8021x']['version'] = b'\x01'
        frames['8021x']['type']    = b'\x01'
        frames['8021x']['length']  = b'\x11'

        self.transport.send_data(frames)
