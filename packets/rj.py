#!/usr/bin/python
# -*- coding: utf-8 -*-


def init(parsers, builders):
    parsers['eapol'].append(rj_eapol_parser)
    builders['ether'].append(rj_ether_builder)


def rj_eapol_parser(frames):
    pass


def rj_ether_builder(frames):
    private = rj_private_builder(frames)

    print(frames['ether']['payload'].hex())
    print(private.hex())
    frames['ether']['payload'] += private


def rj_private_builder(frames):
    """
    '0x00001311' should be RuiJie's vender id.
    """
    private = bytearray()

    # dhcp info
    # 0x0045564d
    field = bytearray()
    field += b'\x00\x00\x13\x11'
    field += b'\x01'  # dhcp enabled
    field += b'\x00\x00\x00\x00'  # ipv4
    field += b'\x00\x00\x00\x00'  # mask
    field += b'\x00\x00\x00\x00'  # gateway
    field += b'\x00\x00\x00\x00'  # primary dns
    dhcp_crc(field)
    dhcp_encode(field)
    private += field

    # program name
    # 0x00455652 ~ 0x004556c8
    private += b'\x00\x00\x13\x11'
    private += b'8021x.exe\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # Version Number
    # 0x004556cc ~ 0x004556e3
    private += b'\x01\x01\x01\x02'

    # ?
    # 0x004556e7 ~ 0x004556f0
    private += b'\xd0'

    private += b'\x00\x00\x13\x11'
    private += b'\x00\x00\x1a\x0c'
    private += b'\x00\x00\x13\x11'
    private += b'\x18\x06'

    # is dhcp auth
    # 0x00455783 ~ 0x004557a4
    private += b'\x00\x00\x00\x01'

    private += b'\x1a\x0e'
    private += b'\x00\x00\x13\x11'
    private += b'\x2d\x08'

    # host mac
    # 0x004557fa ~ 0x00455814
    private += frames['ether']['source']

    private += b'\x1a\x08'
    private += b'\x00\x00\x13\x11'
    private += b'\x2f\x02'

    # alternate dns
    # 0x004559ed ~ 0x00455a88
    field = b'202.114.0.242'
    private += b'\x1a'
    private += (len(field) + 8).to_bytes(1, byteorder='big')
    private += b'\x00\x00\x13\x11'
    private += b'\x76'
    private += (len(field) + 2).to_bytes(1, byteorder='big')
    private += field

    private += b'\x1a\x09'
    private += b'\x00\x00\x13\x11'
    private += b'\x35\x03'

    # ?
    # EAPOL Frame + 0x67c:4
    private += b'\x02'

    private += b'\x1a\x18'
    private += b'\x00\x00\x13\x11'
    private += b'\x36\x12'

    # ?
    # 0x00455b61
    # EAPOL Frame + 0x680:0x10
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    private += b'\x1a\x18'
    private += b'\x00\x00\x13\x11'
    private += b'\x38\x12'

    # ?
    # 0x00455bcf
     # EAPOL Frame + 0x690:0x10
    private += b'\xfe\x80\x00\x00\x00\x00\x00\x00\x27\xa4\xd2\xf0\x0b\xd2\x8c\x23'

    private += b'\x1a\x18'
    private += b'\x00\x00\x13\x11'
    private += b'\x4e\x12'

    # ?
    # 0x00455c75
    # EAPOL Frame + 0x6a0:0x10
    private += b'\x20\x01\x02\x50\x40\x00\x42\x0a\x7f\xed\x89\xc6\xd3\xc4\xf1\x70'

    private += b'\x1a\x88'
    private += b'\x00\x00\x13\x11'
    private += b'\x4d\x82'

    # CVz_APIApp
    private += b'\x62\x34\x36\x34\x38\x39\x36\x64\x38\x31\x33\x35\x65\x65\x31\x64'
    private += b'\x61\x37\x64\x64\x32\x39\x32\x36\x62\x63\x62\x62\x36\x35\x61\x65'
    private += b'\x34\x65\x62\x37\x37\x64\x66\x36\x38\x31\x30\x31\x32\x61\x38\x65'
    private += b'\x35\x32\x63\x65\x38\x62\x66\x35\x36\x36\x31\x32\x35\x31\x39\x34'
    private += b'\x65\x64\x31\x39\x37\x62\x63\x66\x64\x61\x38\x66\x37\x32\x39\x66'
    private += b'\x35\x38\x32\x61\x31\x64\x33\x33\x30\x64\x35\x66\x30\x33\x62\x61'
    private += b'\x34\x38\x32\x34\x35\x61\x38\x33\x32\x35\x66\x31\x32\x31\x35\x65'
    private += b'\x62\x62\x65\x34\x63\x66\x39\x63\x31\x63\x61\x32\x35\x62\x30\x62'

    private += b'\x1a\x28'
    private += b'\x00\x00\x13\x11'
    private += b'\x39\x22'

    # service name
    private += b'internet\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    private += b'\x1a\x48'
    private += b'\x00\x00\x13\x11'
    private += b'\x54\x42'

    # ?
    private += b'\x39\x51\x46\x34\x4d\x31\x59\x52\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    private += b'\x1a\x08'
    private += b'\x00\x00\x13\x11'
    private += b'\x55\x02'

    private += b'\x1a\x09'
    private += b'\x00\x00\x13\x11'
    private += b'\x6f\x17'

    private += b'\x20\x30\x01\xa0\x90\x00\x01\x31\x17\x00\x34\x01\xa1\xd0\x00\x01\x31\x16'

    private += b'RG-SU For Linux V1.0\x00'

    return private


def dhcp_crc(data):
    """ append 2 bytes of crc checksum to dhcp data
    len(data) == 0x15
    """

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
    for byte in data:
        index = (checksum >> 8) ^ byte
        checksum = (checksum << 8) ^ table[index]
        checksum &= 0xFFFF

    data += checksum.to_bytes(2, byteorder='big')


def dhcp_encode(data):
    """ encode dhcp data
    for every byte, do bit swap and bit flip
    len(data) == 0x17
    """

    for i in range(len(data)):
        temp = data[i]
        data[i] = 0

        for _ in range(8):
            data[i] <<= 1
            data[i] |= temp & 1
            temp >>= 1

        data[i] = ~data[i] & 0xFF
