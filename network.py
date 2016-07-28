#!/usr/bin/python
# -*- coding: utf-8 -*-


import socket
import select

import config
from packet import EthernetPacket


X8021_PROTOCOL = 0x888E







# Based on https://gist.github.com/provegard/1536682, which was
# Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
# Only tested on Linux!

from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes.util
import ctypes








def available():
    return ['enp5s0']  # TODO: list all available NICs


def init():
    global _is_up
    global _socket

    global processor
    global timeout
    global mac
    global ipv4
    global mask
    global gateway
    global dns

    _is_up = True

    _socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(X8021_PROTOCOL))
    _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _socket.bind((config.interface, X8021_PROTOCOL))
    _socket.setblocking(False)

    mac = _socket.getsockname()[4]

    try:
        processor.on_eap_start()

        while _is_up:
            readable = select.select([_socket], [], [])[0]  # TODO: enable timeout

            if not readable:
                continue

            raw = _socket.recv(1522)  # 1522 is max ethernet packet size
            raw = bytearray(raw)

            message = EthernetPacket()
            message.from_bytearray(raw)

            eap = message.payload.payload

            if eap.code == 1:
                if eap.type == 1:
                    processor.on_eap_request_identity(message)
                elif eap.type == 4:
                    processor.on_eap_md5_challenge(message)
                else:  # exception
                    pass
            elif eap.code == 3:
                processor.on_eap_success(message)
            elif eap.code == 4:
                processor.on_eap_failure(message)
            else:  # exception
                pass
    except KeyboardInterrupt:
        pass
    finally:
        processor.on_eap_stop()
        _socket.close()

    _socket = None
    timeout = None
    mac = b'\x00\x00\x00\x00\x00\x00'
    ipv4 = 0
    mask = 0
    gateway = 0
    dns = 0


def done():
    global _is_up

    _is_up = False


def send(message: EthernetPacket):
    global _socket

    raw = message.to_bytearray()
    _socket.send(raw)


_is_up = False
_socket = None

processor = None
timeout = None
mac = b'\x00\x00\x00\x00\x00\x00'
ipv4 = 0
mask = 0
gateway = 0
dns = 0












class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_byte * 14),]

class struct_sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', c_ushort),
        ('sin_port', c_uint16),
        ('sin_addr', c_byte * 4)]

class struct_sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', c_ushort),
        ('sin6_port', c_uint16),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', c_byte * 16),
        ('sin6_scope_id', c_uint32)]

class union_ifa_ifu(Union):
    _fields_ = [
        ('ifu_broadaddr', POINTER(struct_sockaddr)),
        ('ifu_dstaddr', POINTER(struct_sockaddr)),]

class struct_ifaddrs(Structure):
    pass
struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p),]

libc = ctypes.CDLL(ctypes.util.find_library('c'))

def ifap_iter(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents

def getfamaddr(sa):
    family = sa.sa_family
    addr = None
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
    elif family == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        addr = inet_ntop(family, sa.sin6_addr)
    return family, addr

class NetworkInterface(object):
    def __init__(self, name):
        self.name = name
        self.index = libc.if_nametoindex(name)
        self.addresses = {}

    def __str__(self):
        return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
            self.name, self.index,
            self.addresses.get(AF_INET),
            self.addresses.get(AF_INET6))

def get_network_interfaces():
    ifap = POINTER(struct_ifaddrs)()
    result = libc.getifaddrs(pointer(ifap))
    if result != 0:
        raise OSError(get_errno())
    del result
    try:
        retval = {}
        for ifa in ifap_iter(ifap):
            name = ifa.ifa_name.decode("UTF-8")
            i = retval.get(name)
            if not i:
                i = retval[name] = NetworkInterface(name)
            family, addr = getfamaddr(ifa.ifa_addr.contents)
            if addr:
                if family not in i.addresses:
                    i.addresses[family] = list()
                i.addresses[family].append(addr)
        return retval.values()
    finally:
        libc.freeifaddrs(ifap)

def get_ip(nic: str):
    for dev in get_network_interfaces():
        if dev.name == nic:
            return dev.addresses.get(AF_INET)
    return None

if __name__ == '__main__':
    print([str(ni) for ni in get_network_interfaces()])
