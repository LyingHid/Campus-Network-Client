#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import eventloop


class RawTransport():
    def __init__(self, config, protocol, loop):
        self.config = config
        self.protocol = protocol
        self.loop = loop

        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x888E))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((config['nic'], 0x888E))
        self.socket.setblocking(False)

        self.address = self.socket.getsockname()[4]
        self.first_writale = True

        watcher = eventloop.FileWatcher(self.socket, eventloop.EVENT_WRITE, self.on_events)
        loop.register(watcher)


    def on_events(self, watcher, events):
        if events & eventloop.EVENT_READ:
            packet = self.socket.recv(1522)

            frames = {}
            frames['raw'] = {}
            frames['raw']['payload'] = packet

            parsers = self.config['packet']['parsers']
            level = 'top'
            while level:
                for parser in parsers[level]:
                    level = parser(frames)

            self.protocol.data_received(frames)

        if events & eventloop.EVENT_WRITE:
            watcher.events = eventloop.EVENT_READ
            self.loop.modify(watcher)

            if self.first_writale:
                self.first_writale = False
                self.protocol.connection_made(self)


    # interface transport
    def send_data(self, frames):
        # TODO: wait for eventloop writable
        builders = self.config['packet']['builders']
        level = 'bottom'
        while level:
            for builder in builders[level]:
                level = builder(frames)

        self.socket.send(frames['raw']['payload'])


    # interface transport
    def get_address(self):
        return self.address
