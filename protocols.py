#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib

from packets import standard
from packets import ruijie
import config
import network


class EapProtocol():
    def __init__(self):
        self.transport = None

        config.db['packet']['parsers']['ether'].insert(0, standard.ether_parser)
        config.db['packet']['parsers']['8021x'].insert(0, standard.x8021_parser)
        config.db['packet']['parsers']['eapol'].insert(0, standard.eapol_parser)

        config.db['packet']['builders']['ether'].insert(0, standard.ether_builder)
        config.db['packet']['builders']['8021x'].insert(0, standard.x8021_builder)
        config.db['packet']['builders']['eapol'].insert(0, standard.eapol_builder)


    # interface protocol
    def connection_made(self, transport):
        self.transport = transport
        self.start_eapol({})


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


    def start_eapol(self, frames):
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

        print('开始认证')


    def response_id(self, frames):
        src_mac = frames['ether']['source'     ]
        dst_mac = frames['ether']['destination']
        frames['ether']['source'     ] = dst_mac
        frames['ether']['destination'] = src_mac

        frames['eapol']['code'    ] = b'\x02'
        frames['eapol']['identity'] = config.db['user']['username']

        self.transport.send_data(frames)

        print('发送用户名')


    def response_md5_challenge(self, frames):
        md5 = hashlib.md5()
        md5.update(frames['eapol']['id'])
        md5.update(config.db['user']['password'])
        md5.update(frames['eapol']['md5 value'])

        src_mac = frames['ether']['source'     ]
        dst_mac = frames['ether']['destination']
        frames['ether']['source'     ] = dst_mac
        frames['ether']['destination'] = src_mac

        frames['eapol']['code'] = b'\x02'
        frames['eapol']['md5 value'] = md5.digest()
        if 'md5 extra data' in frames['eapol']:
            frames['eapol']['md5 extra data'] = config.db['user']['username']

        self.transport.send_data(frames)

        print('发送密码')


    def response_success(self, frames):
        print('认证成功')
        self.transport.lose_connection()


    def response_failure(self, frames):
        print('认证失败')
        self.transport.lose_connection()


class RuijieProtocol(EapProtocol):
    def __init__(self):
        EapProtocol.__init__(self)

        self.round = 0
        self.dhcp = {}
        self.dhcp['ipv4'] = b'\x00\x00\x00\x00'
        self.dhcp['mask'] = b'\x00\x00\x00\x00'
        self.dhcp['gateway'] = b'\x00\x00\x00\x00'
        self.dhcp['dns'] = b'\x00\x00\x00\x00'

        config.db['packet']['parsers']['eapol'].append(ruijie.eapol_parser)
        config.db['packet']['builders']['ether'].append(ruijie.ether_builder)


    def connection_made(self, transport):
        self.round = 1

        EapProtocol.connection_made(self, transport)


    def start_eapol(self, frames):
        if self.round == 1:
            network.detach_network_manager(config.db['nic'])
        frames['ruijie'] = {}
        frames['ruijie']['dhcp'] = self.dhcp

        EapProtocol.start_eapol(self, frames)


    def response_id(self, frames):
        frames['ruijie']['dhcp'] = self.dhcp

        EapProtocol.response_id(self, frames)


    def response_md5_challenge(self, frames):
        frames['eapol']['md5 extra data'] = config.db['user']['username']
        frames['ruijie']['dhcp'] = self.dhcp
        frames['ruijie']['username'] = config.db['user']['username']
        frames['ruijie']['password'] = config.db['user']['password']

        EapProtocol.response_md5_challenge(self, frames)


    def response_success(self, frames):
        if self.round == 1:
            self.round += 1

            print('获取DHCP信息')
            network.attach_network_manager(config.db['nic'])
            network.set_adapter_address(config.db['nic'])
            self.dhcp = network.get_adapter_dhcp_info(config.db['nic'])
            self.start_eapol({})
        else:
            EapProtocol.response_success(self, frames)

            notice = frames['ruijie']['notice'].decode('gbk').replace('\r\n', '\n').strip()
            if len(notice):
                print('通知：')
                print(notice)

            if 'bill' in frames['ruijie']:
                print('计费信息：')
                print(frames['ruijie']['bill'].decode('gbk').strip())


    def response_failure(self, frames):
        EapProtocol.response_failure(self, frames)

        print('通知：')
        print(frames['ruijie']['notice'].decode('gbk').replace('\r\n', '\n').strip())


def get_default():
    """ protocol factory
    the factory can be extended to support other schools
    """
    return RuijieProtocol()
