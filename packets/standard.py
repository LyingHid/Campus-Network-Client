#!/usr/bin/python
# -*- coding: utf-8 -*-


"""
This package defines the interface
between network packets and the program itself.
It parses and builds the standard / public part in packets.

Received packets are parsed to 'frames',
and the infos in the 'frames' are used to build packets to be sent on the wire.

Parameter 'frames' contain key-value pairs,
which are infos being parsed from packets or used to build packets.
The values in key-value pairs should be 'bytes' or 'bytearray'.
Return value indicate further action,
if 'None' is returned, then the parsing or building process completes.
"""


def ether_parser(frames):
    packet = frames['raw']['payload']

    frames['ether'] = {}
    frames['ether']['destination'] = packet[0x0000 : 0x0006]
    frames['ether']['source']      = packet[0x0006 : 0x000C]
    frames['ether']['protocol']    = packet[0x000C : 0x000E]
    if len(packet) > 0x000E:
        frames['ether']['payload'] = packet[0x000E : ]

    return '8021x'


def x8021_parser(frames):
    packet = frames['ether']['payload']

    frames['8021x'] = {}
    frames['8021x']['version'] = packet[0x0000 : 0x0001]
    frames['8021x']['type']    = packet[0x0001 : 0x0002]
    frames['8021x']['length']  = packet[0x0002 : 0x0004]
    if len(packet) <= 0x0004: return
    frames['8021x']['payload'] = packet[0x0004 : ]

    return 'eapol'


def eapol_parser(frames):
    if 'payload' not in frames['8021x']: return
    packet = frames['8021x']['payload']

    frames['eapol'] = {}
    frames['eapol']['code']   = packet[0x0000 : 0x0001]
    frames['eapol']['id']     = packet[0x0001 : 0x0002]
    frames['eapol']['length'] = packet[0x0002 : 0x0004]

    # something I cann't write beautifully
    if frames['eapol']['code'] == b'\x01':  # eap request
        frames['eapol']['type'] = packet[0x0004 : 0x0005]

        if frames['eapol']['type'] == b'\x04':  # md5 chanllenge
            length = int.from_bytes(frames['eapol']['length'], byteorder='big', signed=False)
            frames['eapol']['md5 value size'] = packet[0x0005 : 0x0006]
            size = int.from_bytes(frames['eapol']['md5 value size'], byteorder='big', signed=False)
            frames['eapol']['md5 value'] = packet[0x0006 : 0x0006 + size]

            if length > 0x0006 + size:  # md5 extra data
                frames['eapol']['md5 extra data'] = packet[0x0006 + size : length]

    # no chance to parse a response packet
    # if frames['eapol']['code'] = b'\x02': pass

    return


def ether_builder(frames):
    packet = bytearray()

    packet += frames['ether']['destination']
    packet += frames['ether']['source']
    packet += frames['ether']['protocol']
    packet += frames['ether']['payload']

    frames['raw']['payload'] = packet

    return


def x8021_builder(frames):
    packet = bytearray()

    length = len(frames['8021x']['payload']) if 'payload' in frames['8021x'] else 0
    frames['8021x']['length'] = length.to_bytes(2, byteorder='big')

    packet += frames['8021x']['version']
    packet += frames['8021x']['type']
    packet += frames['8021x']['length']
    if 'payload' in frames['8021x']:
        packet += frames['8021x']['payload']

    frames['ether']['payload'] = packet

    return 'ether'


def eapol_builder(frames):
    if 'eapol' not in frames: return '8021x'

    packet = bytearray()

    packet += frames['eapol']['code']
    packet += frames['eapol']['id']
    packet += frames['eapol']['length']

    # something I cann't write beautifully
    # no chance to build a request packet
    # if frames['eapol']['code'] == b'\x01':

    if frames['eapol']['code'] == b'\x02':  # eap response
        packet += frames['eapol']['type']

        if frames['eapol']['type'] == b'\x01':
            packet += frames['eapol']['identity']
        else:  # frames['eapol']['type'] == b'\x04':
            packet += frames['eapol']['md5 value size']
            packet += frames['eapol']['md5 value']

            if 'md5 extra data' in frames['eapol']:
                packet += frames['eapol']['md5 extra data']

    length = len(packet)
    packet[0x0002 : 0x0004] = length.to_bytes(2, byteorder='big')

    frames['8021x']['payload'] = packet

    return '8021x'
