#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib

#from . import extra


def init(parsers, builders):
    parsers['eapol'].append(ruijie_eapol_parser)
    builders['ether'].append(ruijie_ether_builder)


def ruijie_eapol_parser(frames):
    """ Simulate RuiJie's function 'ParsePrivateProperty'
    ParsePrivateProperty(uchar packet[], int packet_length, EAPOLFrame frame[])
    '0x00001311' should be RuiJie's vender id
    """

    frames['ruijie'] = {}

    if frames['eapol']['code'] == b'\x01':
        if frames['eapol']['type'] == b'\x04':
            # 'md5 value' will be used to build private frame
            frames['ruijie']['md5 value'] = frames['eapol']['md5 value']

            index = 4

            # if frames['eapol']['md5 extra data'][index : index + 3] == b'\x2e\x03\x01':
            #     pass
            index += 3

            # md5 extra data contains service list
            # services are joined by '@'
            if frames['eapol']['md5 extra data'][index : index + 5] == b'\x00\x00\x13\x11\x66':
                index += 5
                length = frames['eapol']['md5 extra data'][index]
                index += 1
                services = frames['eapol']['md5 extra data'][index : index + length]
                services = services.split(b'@')

                frames['ruijie']['services'] = services

    elif frames['eapol']['code'] == b'\x03':
        index = 4  # location at extra data

        # notification (gbk encode)
        # 0x00001311 length:2 string:length
        # 0x00457032 ~ 0x004570d0
        # EAPOLFrame+0x38:4 vendor id 0x00001311
        # EAPOLFrame+0x3e:0x5dc utf-8 string
        index += 4  # location at strng length
        length = int.from_bytes(frames['8021x']['payload'][index : index + 2], byteorder='big')
        index += 2  # location at string
        notice = frames['8021x']['payload'][index : index + length]

        frames['ruijie']['notice'] = notice
        index += length

        # 0x00001311 0x0069 content:0x0069
        # 0x004570d5 ~
        # EAPOLFrame+0x620:4 vendor id 0x00001311
        # EAPOLFrame+0x62c:4 first dword of content
        # xxxx valid content length

        # 0x00001311 01 00
        # passed

        # 0x00001311 xx xx
        # 0x004570e0 ~ 0x00457196
        # xx xx EAPOLFrame+0x63c 0x63d

        # 0x00001311 xx xx encoded:15
        # 0x004571ab ~ 0x00457205
        # EAPOLFrame+0x640:4 vendor id 0x00001311
        # xx xx EAPOLFrame+0x644 0x645
        # encoded
        # 0x00001311 xx xx yyyyyyyy zzzzzzzz uu
        # 0x0045721a ~
        # EAPOLFrame+0x648:4 vendor id 0x00001311
        # xx xx EAPOLFrame+0x64c 0x64d
        # yyyyyyyy EAPOLFrame+0x650 (mentohust echo key)
        # zzzzzzzz*0x3e8 EAPOLFrame+0x654
        # uu EAPOLFrame+0x658

        # reach optional switch case
        # 0x0045730e ~ 0x00457354

        # 0x00001311 56 06 yyyyyyyy
        # 56 06 switch_case+0x37 length+2
        # ? 计费提示
        # yyyyyyyy auto_reconnect CtrlThread+0x33e 0x340

        # 0x00001311 5a 06 yyyyyyyy
        # 5a 06 switch_case+0x37 length+2
        # yyyyyyyy indicate_port CtrlThread+0x404

        # 0x00001311 5b 06 yyyyyyy
        # 5b 06 switch_case+0x37 length+2
        # yyyyyyyy indicate_serv_ip CtrlThread+0x400

        # 0x00001311 5c 0a yyyyyyyyyyyyyyyy
        # 5c 08 switch_case+0x37 length+2
        # RC4(
        #     yyyyyyyyyyyyyyyy,
        #     rsp+0x30:10,  // result
        #     com.ruijie.www", // rsp+0x20:15, including '\0'
        #     8
        # )
        # stored in CtrlThread+0x410:8
        # encrypt key
        # 0x00457c3b ~ 0x00457d0d

        # 0x00001311 5d 0a yyyyyyyyyyyyyyyy
        # 5d 0a switch_case+0x37 length+2
        # RC4(
        #     yyyyyyyyyyyyyyyy,
        #     rsp+0x30:10,  // result
        #     com.ruijie.www", // rsp+0x20:15, including '\0'
        #     8
        # )
        # stored in CtrlThread+0x418:8
        # encrypt iv
        # 0x00457b27 ~ 0x00457bf4

        # 0x00001311 5e 0a yyyyyyyyyyyyyyyy
        # 5e 0a switch_case+0x37 length+2
        # yyyyyyyyyyyyyyyy server utc time CtrlThread+0x420

        # 0x00001311 6e 06 yyyyyyyyyyyy
        # 6e 06 switch_case+0x37 length+2
        # yyyyyyyyyyyy msg client port CtrlThread+0x408

        # 0x00001311 79 03
        # 0x00001311 80 06
        # 0x00001311 98 06


def ruijie_ether_builder(frames):
    private = ruijie_private_builder(frames)
    frames['raw']['payload'] += private


def ruijie_private_builder(frames):
    """ Simulate RuiJie's function 'AppendPrivateProperty'
    AppendPrivateProperty(uchar packet[], int &next_index, EAPOLFrame frame[])
    '0x00001311' should be RuiJie's vender id
    """

    private = bytearray()

    # dhcp ip info
    # DhcpIpInfoToUChar(unsigned char *, EAPOLFrame *)
    field = bytearray()
    field += b'\x00\x00\x13\x11'
    # is dhcp enabled:1 < EAPOLFrame+0x65c:4 < CtrlThread+0x29c:4
    field += b'\x01'  # dhcp is enabled in HUST
    # ipv4:4 < EAPOLFrame+0x660:4 < CtrlThread+0x2a0:4
    field += b'\x00\x00\x00\x00'
    # mask:4 < EAPOLFrame+0x664:4 < CtrlThread+0x2a4:4
    field += b'\x00\x00\x00\x00'
    # gateway:4 < EAPOLFrame+0x668:4 < CtrlThread+0x2a8:4
    field += b'\x00\x00\x00\x00'
    # primary dns:4 < EAPOLFrame+0x66c:4 < CtrlThread+0x2ac:4
    field += b'\xca\x72\x00\x83'  # 202.114.0.131 in HUST
    dhcp_ip_crc(field)
    dhcp_ip_encode(field)
    private += field

    # program name
    # 0x00455652 ~ 0x004556bb
    private += b'\x00\x00\x13\x11'
    # EncapProgrammName(std::string, unsigned char *)
    private += b'8021x.exe\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # Version Number
    # 0x004556cc ~ 0x004556e3
    # EncapUCharVersionNumber(unsigned char *)
    # version:4 < theApp+8:4
    private += b'\x01\x01\x01\x02'

    # ?
    # 0x004556e7 ~ 0x004556f3
    # EAPOLFrame+0x6c0:1
    private += b'\x00'  # ? first packet '\x00', then '\xd0', uninitialized data

    private += b'\x00\x00\x13\x11'

    # size of following content
    # 0x00455720 ~ 0x00455728
    private += b'\x00\x00'
    size1 = len(private)

    private += b'\x1a\x0c'
    private += b'\x00\x00\x13\x11'
    private += b'\x18\x06'

    # is dhcp enabled:1 < CtrlThread+0x29c:4
    # 0x00455778 ~ 0x004557ae
    # CContextControlThread::IsDhcpAuth()
    private += b'\x00\x00\x00\x01'  # dhcp is enabled in HUST

    private += b'\x1a\x0e'
    private += b'\x00\x00\x13\x11'
    private += b'\x2d\x08'

    # host mac
    # 0x004557fa ~ 0x00455811
    private += frames['ether']['source']

    private += b'\x1a'

    md5_anchor1 = len(private)

    private += b'\x08'  # updated in state 'response md5 challenge'

    private += b'\x00\x00\x13\x11'
    private += b'\x2f'

    md5_anchor2 = len(private)

    private += b'\x02'  # updated in state 'response md5 challenge'

    # md5 challenge branch
    if 'eapol' in frames and frames['eapol']['type'] == b'\x04':
        # RadiusEncrpytPwd
        # (
        #     uchar challenge[], u challenge_length,
        #     uchar username[], u username_length,
        #     uchar result[]
        # )
        field = password_encode(
            frames['ruijie']['username'],
            frames['ruijie']['password'],
            frames['ruijie']['md5 value']
        )
        private += field

        private[md5_anchor1] += len(field)
        private[md5_anchor2] += len(field)

    # secondary dns
    # 0x004559ed ~ 0x00455a88
    # sym.get_alternate_dns
    # cat /etc/resolv.conf 2>&- | awk '{if ($1=="nameserver") {print $2}}' | awk 'NR>1'
    field = b'202.114.0.242'  # if no 2nd dns exists, " field = b'' "
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
    # 0x00455af8 ~ 0x00455b0f
    # EAPOLFrame+0x67c:4 < CtrlThread+0x2bc:4
    private += b'\x02'  # seems to be constant

    private += b'\x1a\x18'
    private += b'\x00\x00\x13\x11'
    private += b'\x36\x12'

    # ?
    # 0x00455b5e ~ 0x00455b7d
    # EAPOLFrame+0x680:0x10 < CtrlThread+0x2c0:0x10
    # seems to be constant
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    private += b'\x1a\x18'
    private += b'\x00\x00\x13\x11'
    private += b'\x38\x12'

    # ?
    # 0x00455bcc ~ 0x00455beb
    # EAPOLFrame+0x690:0x10 < CtrlThread+0x2d0:0x10
    # seems to be constant
    private += b'\xfe\x80\x00\x00\x00\x00\x00\x00\x27\xa4\xd2\xf0\x0b\xd2\x8c\x23'

    private += b'\x1a\x18'
    private += b'\x00\x00\x13\x11'
    private += b'\x4e\x12'

    # ?
    # 0x00455c66 ~ 0x00455c92
    # EAPOLFrame+0x6a0:0x10 < CtrlThread+0x2e0:0x10
    # seems to be constant
    private += b'\x20\x01\x02\x50\x40\x00\x42\x0a\x7f\xed\x89\xc6\xd3\xc4\xf1\x70'

    private += b'\x1a\x88'
    private += b'\x00\x00\x13\x11'
    private += b'\x4d\x82'

    # ? fingerprint
    # 0x00455ca1 ~ 0x00455cde
    # CVz_APIApp::CVz_APIApp()
    # CVz_APIApp::Vz_API(char *, char *, char const *0x4a9c62)
    # 0x00455d40 ~ 0x00455e0d
    # seem same when 'start' 'response id' and 'logoff'
    # different when 'md5 challenge'
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
    # CtrlThread+0x258:8 (pointer to service name)
    private += b'internet\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    private += b'\x1a\x48'
    private += b'\x00\x00\x13\x11'
    private += b'\x54\x42'

    # ?
    # 0x00455f82 ~ 0x00456005
    # CtrlThread+0x10f0:8 (pointer to ? string)
    # seems to be constant
    private += b'9QF4M1YR\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    private += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # ?
    # 0x0045600f ~ 0x0045611f
    # CtrlThread+0x4d8:8 (pointer to ? string)
    # strlen + 8
    # seems to be constant
    private += b'\x1a'
    private += b'\x08'
    private += b'\x00\x00\x13\x11'
    private += b'\x55'
    # strlen + 2
    # seems to be constant
    private += b'\x02'
    # append '? string' to 'private' (string is empty)

    private += b'\x1a\x09'
    private += b'\x00\x00\x13\x11'
    private += b'\x62\x03'

    # branch @ 0x00456179
    # the result is same
    private += b'\x00'

    private += b'\x1a\x09'
    private += b'\x00\x00\x13\x11'
    private += b'\x70\x03'

    # if 64 bit
    # Is64BIT() if is 64-bit
    # always behave as a 64-bit machine
    private += b'\x40'
    # else
    # private += b'\x20'

    # rg-su
    field = b'RG-SU For Linux V1.0'
    # 0x00456268 ~ 0x0045632a
    private += b'\x1a'
    # strlen + '\0' + 8
    private += (len(field) + 1 + 8).to_bytes(1, byteorder='big')
    private += b'\x00\x00\x13\x11'
    private += b'\x6f'
    # strlen + '\0' + 2
    private += (len(field) + 1 + 2).to_bytes(1, byteorder='big')
    # 0x00456410 ~ 0x0045641b
    private += field

    private += b'\x00'

    size2 = len(private)
    field = size2 - size1
    private[size1 - 2 : size1] = field.to_bytes(2, byteorder='big')

    return private


def dhcp_ip_crc(data):
    """ append 2 bytes of crc checksum to dhcp ip data
    xcrc16(void * / unsigned char *, int 0x15)
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


def dhcp_ip_encode(data):
    """ encode dhcp ip data
    encode(unsigned char *, int 0x17)
    for every byte, do bit swap and bit flip
    run 'encode' twice to decode
    """

    for i in range(len(data)):
        temp = data[i]
        data[i] = 0

        for _ in range(8):
            data[i] <<= 1
            data[i] |= temp & 1
            temp >>= 1

        data[i] = ~data[i] & 0xFF


def password_encode(username, password, challenge):
    block = challenge
    cipher = bytearray()

    while len(password):
        plain = password[0 : 16]
        password = password[16: ]

        md5 = hashlib.md5()
        md5.update(username)
        md5.update(block)
        block = bytearray(md5.digest())

        for i in range(len(plain)):
            block[i] ^= plain[i]

        cipher += block

    return cipher


def test():
    print('>>> dhcp ip')
    field = bytearray()
    field += b'\x00\x00\x13\x11'
    field += b'\x01'
    field += b'\x00\x00\x00\x00'
    field += b'\x00\x00\x00\x00'
    field += b'\x00\x00\x00\x00'
    field += b'\xca\x72\x00\x83'
    dhcp_ip_crc(field)
    print(field.hex())
    print('0000131101000000000000000000000000ca7200839cfd')
    dhcp_ip_encode(field)
    print(field.hex())
    print('ffff37777fffffffffffffffffffffffffacb1ff3ec640')

    print()

    print('>>> password')
    field = password_encode(
        b'Hello',
        b'World',
        bytes.fromhex('becd6e05415013baa721445b8697ac42')
    )
    print(field.hex())
    print('3587ced626ddc75a61be8575c50fe903')


if __name__ == '__main__':
    test()
