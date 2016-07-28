#!/usr/bin/python
# -*- coding: utf-8 -*-


import hashlib
import subprocess

import config
import network
from packet import EthernetPacket, X8021Packet, EAPPacket, Packet


def on_eap_start():
    _packet_cache.clear()

    x8021 = X8021Packet()
    x8021.version = 1
    x8021.type = 1
    x8021.length = 0

    ether = EthernetPacket()
    ether.source = network.mac
    ether.destination = _SHABBY_MAC
    ether.protocol = 0x888E
    ether.payload = x8021
    ether.padding = _Padding().to_bytearray()

    network.send(ether)


def on_eap_request_identity(message: EthernetPacket):
    if message.destination == _X8021_MAC:
        # Shabby rj doesn't use standard 802.1X MAC, just ignore it.
        print("The shabby rj is making noise")
        return

    ether = message
    x8021 = ether.payload  # type: X8021Packet
    eap = x8021.payload  # type: EAPPacket

    eap.code = 2
    eap.identity = config.username.encode()

    ether.destination, ether.source = ether.source, ether.destination
    ether.padding = _Padding().to_bytearray()

    _packet_cache[eap.id] = ether
    network.send(ether)


def on_eap_md5_challenge(message):
    ether = message
    x8021 = ether.payload  # type: X8021Packet
    eap = x8021.payload  # type: EAPPacket

    md5 = hashlib.md5()
    md5.update(eap.id.to_bytes(1, byteorder='big'))
    md5.update(config.password.encode())
    md5.update(eap.md5_value)

    eap.code = 2
    eap.md5_value = md5.digest()
    eap.extra = config.username.encode()

    ether.destination, ether.source = ether.source, ether.destination
    ether.padding = _Padding().to_bytearray()

    _packet_cache[eap.id] = network.send(ether)


def on_eap_success(message):
    global _round

    # ether = message
    # x8021 = ether.payload  # type: X8021Packet
    # eap = x8021.payload  # type: EAPPacket

    if _round == 0:
        _round += 1
        subprocess.call(['dhclient', config.interface])
        on_eap_start()
    else:
        _round = 0
        print("Shabby rj has been successfully fooled.")
        network.done()


def on_eap_failure(message):
    # ether = message
    # x8021 = ether.payload  # type: X8021Packet
    # eap = x8021.payload  # type: EAPPacket

    print("Shabby rj refused us, dame it.")
    network.done()


def on_eap_timeout():
    pass


def on_eap_stop():
    pass


class _Padding(Packet):
    def to_bytearray(self):
        packet = bytearray()
        packet.extend(b'\x00\x00\x13\x11')
        packet.extend(b'\x01')  # Enable DHCP
        packet.extend(network.ipv4.to_bytes(4, byteorder='big'))
        packet.extend(network.mask.to_bytes(4, byteorder='big'))
        packet.extend(network.gateway.to_bytes(4, byteorder='big'))
        packet.extend(network.dns.to_bytes(4, byteorder='big'))
        packet.extend(self._checksum(packet))
        self._mirror_n_flip(packet)
        self._obscure(packet)

        return packet

    @staticmethod
    def _checksum(packet):
        table = [
            0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
            0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
            0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
            0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
            0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
            0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
            0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
            0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
            0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
            0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
            0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
            0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
            0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
            0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
            0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
            0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
            0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
            0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
            0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
            0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
            0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
            0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
            0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
            0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
            0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
            0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
            0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
            0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
            0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
            0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
            0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
            0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
        ]
        checksum = 0

        for byte in packet:
            index = (checksum >> 8) ^ byte
            checksum = (checksum << 8) ^ table[index]
            checksum &= 0xFFFF

        return checksum.to_bytes(2, byteorder='big')

    @staticmethod
    def _mirror_n_flip(packet):
        for i in range(len(packet)):
            temp = packet[i]
            packet[i] = 0

            for _ in range(8):
                packet[i] <<= 1
                packet[i] |= temp & 1
                temp >>= 1

            packet[i] = ~packet[i] & 0xFF

    @staticmethod
    def _obscure(packet):
        obscure = bytearray(
            b'\x00\x00\x13\x11\x38\x30\x32\x31'
            b'\x78\x2e\x65\x78\x65\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x01\x00\x01\x00'
            b'\x00\x00\x00\x13\x11\x00\x28\x1a'
            b'\x28\x00\x00\x13\x11\x17\x22\x91'
            b'\x66\x64\x93\x67\x60\x65\x62\x62'
            b'\x94\x61\x69\x67\x63\x91\x93\x92'
            b'\x68\x66\x93\x91\x66\x95\x65\xaa'
            b'\xdc\x64\x98\x96\x6a\x9d\x66\x00'
            b'\x00\x13\x11\x18\x06\x02\x00\x00'
            b'\x01\x00\x00\x00\x00\x00\x00\x00'
        )

        packet.extend(obscure)


_X8021_MAC = b'\x01\x80\xC2\x00\x00\x03'
_SHABBY_MAC = b'\x01\xd0\xf8\x00\x00\x03'

_round = 0
_shabby_mac = None
_packet_cache = {}
