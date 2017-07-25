#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import selectors


class RawTransport():
    def __init__(self, nic, parsers, builders, protocol, eventloop):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x888E))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((nic, 0x888E))
        self.socket.setblocking(False)

        self.address = self.socket.getsockname()[4]

        self.parsers  = parsers
        self.builders = builders

        self.protocol = protocol

        self.eventloop = eventloop
        self.eventloop.register(self.socket, selectors.EVENT_WRITE, self.on_events)

        self.first_writale = True


    def on_events(self, events):
        if events & selectors.EVENT_READ:
            packet = self.socket.recv(1522)

            frames = {}
            frames['raw'] = {}
            frames['raw']['payload'] = packet

            level = 'top'
            while level:
                for parser in self.parsers[level]:
                    level = parser(frames)

            self.protocol.data_received(frames)

        if events & selectors.EVENT_WRITE:
            self.eventloop.modify(self.socket, selectors.EVENT_READ, self.on_events)

            if self.first_writale:
                self.first_writale = False
                self.protocol.connection_made(self)


    # interface transport
    def send_data(self, frames):
        # TODO: wait for eventloop writable
        level = 'bottom'
        while level:
            for builder in self.builders[level]:
                level = builder(frames)

        self.socket.send(frames['raw']['payload'])


    # interface transport
    def get_address(self):
        return self.address
