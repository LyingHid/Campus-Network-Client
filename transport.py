#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket

import eventloop
import network
import config


class RawTransport():
    def __init__(self, protocol, loop):
        self.protocol = protocol
        self.loop = loop

        self.socket, self.address = network.get_adapter_socket(config.db['nic'])

        self.first_writale = True
        self.last_receive = False
        self.send_buffer = bytearray()

        self.watcher = eventloop.FileWatcher(self.socket, eventloop.EVENT_WRITE, self.on_events)
        self.loop.register(self.watcher)


    def on_events(self, watcher, events):
        if events & eventloop.EVENT_READ:
            packet = self.socket.recv(1522)

            frames = {}
            frames['raw'] = {}
            frames['raw']['payload'] = packet

            parsers = config.db['packet']['parsers']
            level = 'ether'
            while level:
                for parser in parsers[level]:
                    level = parser(frames)

            self.protocol.data_received(frames)

        if events & eventloop.EVENT_WRITE:
            if self.first_writale:
                self.first_writale = False

                watcher.events = eventloop.EVENT_READ
                self.loop.modify(watcher)

                self.protocol.connection_made(self)
            else:
                nsent = self.socket.send(self.send_buffer)
                self.send_buffer = self.send_buffer[nsent:]

                if len(self.send_buffer) == 0:
                    if self.last_receive:
                        self.loop.unregister(watcher)
                        self.protocol.connection_lost(None)
                        self.loop.stop()
                    else:
                        watcher.events = eventloop.EVENT_READ
                        self.loop.modify(watcher)


    # interface transport
    def send_data(self, frames):
        builders = config.db['packet']['builders']
        level = 'eapol'
        while level:
            for builder in builders[level]:
                level = builder(frames)

        self.send_buffer += frames['raw']['payload']

        if self.watcher.events & eventloop.EVENT_WRITE == 0:
            self.watcher.events |= eventloop.EVENT_WRITE
            self.loop.modify(self.watcher)


    # interface transport
    def lose_connection(self):
        self.last_receive = True

        if len(self.send_buffer) == 0:
            self.loop.unregister(self.watcher)
            self.protocol.connection_lost(None)
            self.loop.stop()


    # interface transport
    def get_address(self):
        return self.address
