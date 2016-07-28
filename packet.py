#!/usr/bin/python
# -*- coding: utf-8 -*-


class Packet:
    def from_bytearray(self, raw):
        return bytearray()

    def to_bytearray(self):
        return bytearray()


class EthernetPacket(Packet):
    def __init__(self):
        self.destination = bytearray()
        self.source = bytearray()
        self.protocol = 0
        self.payload = Packet()
        self.padding = bytearray()
        # The FCS is provided by hardware, we must not care about it.

    def from_bytearray(self, raw):
        self.destination = raw[0 : 6]
        self.source = raw[6 : 12]
        self.protocol = int.from_bytes(raw[12 : 14], byteorder='big', signed=False)
        del raw[:14]

        self.payload = X8021Packet()

        self.padding = self.payload.from_bytearray(raw)

        return raw

    def to_bytearray(self):
        packet = bytearray()
        packet.extend(self.destination)
        packet.extend(self.source)
        packet.extend(self.protocol.to_bytes(2, byteorder='big'))
        packet.extend(self.payload.to_bytearray())
        packet.extend(self.padding)

        if len(packet) < 60:
            packet.extend(bytearray(60 - len(packet)))

        return packet


class X8021Packet(Packet):
    def __init__(self):
        self.version = 1
        self.type = 0
        self.length = 0
        self.payload = Packet()

    def from_bytearray(self, raw):
        self.version = int.from_bytes(raw[0 : 1], byteorder='big', signed=False)
        self.type = int.from_bytes(raw[1 : 2], byteorder='big', signed=False)
        self.length = int.from_bytes(raw[2 : 4], byteorder='big', signed=False)
        del raw[:4]

        if self.length > 0:
            self.payload = EAPPacket()
            return self.payload.from_bytearray(raw)

        return raw

    def to_bytearray(self):
        payload = self.payload.to_bytearray()

        self.length = len(payload)

        packet = bytearray()
        packet.extend(self.version.to_bytes(1, byteorder='big'))
        packet.extend(self.type.to_bytes(1, byteorder='big'))
        packet.extend(self.length.to_bytes(2, byteorder='big'))
        packet.extend(payload)

        return packet


class EAPPacket(Packet):
    def __init__(self):
        self.code = 0
        self.id = 0
        self.length = 0

        self.type = 4

        self.identity = bytearray()

        self.md5_size = 0
        self.md5_value = bytearray()
        self.extra = bytearray()

    def from_bytearray(self, raw):
        self.code = int.from_bytes(raw[0 : 1], byteorder='big', signed=False)
        self.id = int.from_bytes(raw[1 : 2], byteorder='big', signed=False)
        self.length = int.from_bytes(raw[2 : 4], byteorder='big', signed=False)

        if self.code == 1:  # request
            self.type = int.from_bytes(raw[4 : 5], byteorder='big', signed=False)
            if self.type == 4:  # MD5 Challenge
                self.md5_size = int.from_bytes(raw[5 : 6], byteorder='big', signed=False)
                self.md5_value = raw[6 : 6 + self.md5_size]
                self.extra = int.from_bytes(raw[6 + self.md5_size: self.length], byteorder='big', signed=False)
        elif self.code == 2:  # response
            self.type = int.from_bytes(raw[4 : 5], byteorder='big', signed=False)
            if self.type == 1:
                self.identity = raw[5 : self.length]
            elif self.type == 4:  # MD5 Challenge
                self.md5_size = int.from_bytes(raw[5: 6], byteorder='big', signed=False)
                self.md5_value = raw[6: 6 + self.md5_size]
                self.extra = int.from_bytes(raw[6 + self.md5_size: self.length], byteorder='big', signed=False)
            else:
                pass
        else:  # success or failure
            pass

        del raw[: self.length]

        return raw

    def to_bytearray(self):
        packet = bytearray()
        packet.extend(self.code.to_bytes(1, byteorder='big'))
        packet.extend(self.id.to_bytes(1, byteorder='big'))
        packet.extend(b'\x00\x00')  # place holder for length

        if self.code == 1:  # request
            packet.extend(self.type.to_bytes(1, byteorder='big'))
            if self.type == 4:  # MD5 Challenge
                self.md5_size = len(self.md5_value)
                packet.extend(self.md5_size.to_bytes(1, byteorder='big'))
                packet.extend(self.md5_value)
                packet.extend(self.extra)
        elif self.code == 2:  # response
            packet.extend(self.type.to_bytes(1, byteorder='big'))
            if self.type == 1:
                packet.extend(self.identity)
            elif self.type == 4:  # MD5 Challenge
                self.md5_size = len(self.md5_value)
                packet.extend(self.md5_size.to_bytes(1, byteorder='big'))
                packet.extend(self.md5_value)
                packet.extend(self.extra)
            else:
                pass
        else:  # success or failure
            pass

        self.length = len(packet)
        packet[2:4] = self.length.to_bytes(2, byteorder='big')

        return packet
