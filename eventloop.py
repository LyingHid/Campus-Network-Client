#!/usr/bin/python
# -*- coding: utf-8 -*-

import selectors
import heapq
import time


EVENT_READ = selectors.EVENT_READ
EVENT_WRITE = selectors.EVENT_WRITE


class FileWatcher():
    def __init__(self, file, events, callback, data=None):
        self.file = file
        self.events = events
        self.callback = callback
        self.data = data
        self.eventloop = None


class TimeWatcher():
    def __init__(self, first, repeat, callback, data=None):
        self.first = first
        self.repeat = repeat
        self.callback = callback
        self.data = data
        self.eventloop = None
        self.timestamp = None


class Eventloop():
    def __init__(self):
        self.goon = True
        self.selector = selectors.DefaultSelector()
        self.files = {}
        self.timers = []


    def register(self, watcher):
        watcher.eventloop = self

        if isinstance(watcher, FileWatcher):
            self.selector.register(watcher.file, watcher.events, watcher)


    def unregister(self, watcher):
        watcher.eventloop = None

        if isinstance(watcher, FileWatcher):
            self.selector.unregister(watcher.file)


    def run(self):
        while self.goon:
            file_events = self.selector.select()

            for key, events in file_events:
                watcher = key.data
                watcher.callback(watcher, events)


    def stop(self):
        self.goon = False


def test():
    import socket
    import struct


    def sock_callback(watcher, events):
        data = watcher.file.recv(1)
        data = struct.unpack("!b", data)[0]

        print("socket data", data)

        if data == 5:
            eventloop.unregister(watcher)
        if data == 6:
            eventloop.unregister(watcher)
            eventloop.stop()
            return

        data = data + 1
        data = struct.pack("!b", data)
        watcher.file.send(data)


    eventloop = Eventloop()
    sock_a, sock_b = socket.socketpair()
    watcher_a = FileWatcher(sock_a, EVENT_READ, sock_callback)
    watcher_b = FileWatcher(sock_b, EVENT_READ, sock_callback)
    eventloop.register(watcher_a)
    eventloop.register(watcher_b)

    sock_a.send(b'\x00')
    eventloop.run()


if __name__ == "__main__":
    test()
