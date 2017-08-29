#!/usr/bin/python
# -*- coding: utf-8 -*-

import selectors
import socket
import heapq
import time
import signal


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
        self.repeat = repeat  # one pass timer when 'repeat == 0'
        self.callback = callback
        self.data = data
        self.eventloop = None
        self.timestamp = None


class SignalWatcher():
    def __init__(self, number, callback, data=None):
        self.number = number
        self.callback = callback
        self.data = data
        self.eventloop = None


class Eventloop():
    def __init__(self):
        self.goon = True
        self.selector = selectors.DefaultSelector()
        self.timers = []
        self.signals = {}
        self.signal_frames = {}

        # spcket pair with signal to file descriptor
        self.send_pair, self.recv_pair = socket.socketpair()
        self.send_pair.setblocking(False)
        self.recv_pair.setblocking(False)
        self.pair_watcher = FileWatcher(self.recv_pair, EVENT_READ, self.pair_callback)
        self.register(self.pair_watcher)


    def register(self, watcher):
        watcher.eventloop = self

        if isinstance(watcher, FileWatcher):
            self.selector.register(watcher.file, watcher.events, watcher)
        elif isinstance(watcher, TimeWatcher):
            watcher.timestamp = watcher.first + time.monotonic()
            heapq.heappush(self.timers, (watcher.timestamp, watcher))
        else:  # no check to ensure we have a SignalWatcher here
            number = watcher.number
            if number in self.signals:
                raise ValueError("signal is already registered")
            self.signals[number] = watcher
            signal.signal(number, self.signal_callback)
            signal.set_wakeup_fd(self.send_pair.fileno())


    # modify untested and unused
    def modify(self, watcher):
        if isinstance(watcher, FileWatcher):
            self.selector.modify(watcher.file, watcher.events, watcher)
        elif isinstance(watcher, TimeWatcher):
            # only 'repeat' member can be changed
            # it will not take effect until it is popped out from the heap
            # and re-pushed into the heap
            pass
        else:
            if watcher.number not in self.signals:
                raise ValueError("signal is not registered")


    def unregister(self, watcher):
        watcher.eventloop = None

        if isinstance(watcher, FileWatcher):
            self.selector.unregister(watcher.file)
        elif isinstance(watcher, TimeWatcher):
            # using flag to indicate deletion
            i = self.timers.index((watcher.timestamp, watcher))
            self.timers[i] = (watcher.timestamp, None)
        else:
            number = watcher.number
            if number not in self.signals:
                raise ValueError("signal is not registered")
            if number == signal.SIGINT:
                signal.signal(number, signal.default_int_handler)
            else:
                signal.signal(number, signal.SIG_DFL)
            del self.signals[number]
            if len(self.signals) == 0:
                signal.set_wakeup_fd(-1)


    def run(self):
        if self.goon == False:
            raise StopIteration("cannot resume a stopped eventloop")

        while self.goon:
            if len(self.timers):
                timeout = self.timers[0][0] - time.monotonic()
                if timeout <= 0: timeout = 0
            else:
                timeout = None

            file_events = self.selector.select(timeout)

            # timer handling
            timestamp = time.monotonic() + 0.05
            while len(self.timers) and self.timers[0][0] < timestamp:
                watcher = self.timers[0][1]
                if watcher:
                    watcher.callback(watcher, timestamp)

                    if self.timers[0][1] and watcher.repeat:
                        watcher.timestamp += watcher.repeat
                        heapq.heappushpop(self.timers, (watcher.timestamp, watcher))
                    else:
                        heapq.heappop(self.timers)
                else:
                    heapq.heappop(self.timers)

            # file handling
            for key, events in file_events:
                watcher = key.data
                watcher.callback(watcher, events)


    # private. I don't want use '_' to indicate private methods
    def pair_callback(self, watcher, events):
        data = self.recv_pair.recv(1024)
        for number in data:
            watcher = self.signals[number]
            watcher.callback(watcher, self.signal_frames[number])
            del self.signal_frames[number]


    # private. I don't want use '_' to indicate private methods
    def signal_callback(self, number, frame):
        if number in self.signals:
            self.signal_frames[number] = frame


    def stop(self):
        self.unregister(self.pair_watcher)
        self.send_pair.close()
        self.recv_pair.close()
        self.goon = False


def test():
    import struct


    def sock_callback(watcher, events):
        data = watcher.file.recv(1)
        data = struct.unpack("!b", data)[0]

        print("socket data", data)

        if data == 5:
            eventloop.unregister(watcher)
        if data == 6:
            eventloop.unregister(watcher)
            return

        data = data + 1
        data = struct.pack("!b", data)
        watcher.file.send(data)


    def time_callback(watcher, stamp):
        print("time", stamp)

        watcher.count += 1
        if watcher.count == 5:
            eventloop.unregister(watcher)


    def signal_callback(watcher, number):
        print("sig int received")
        eventloop.unregister(watcher)
        eventloop.stop()


    eventloop = Eventloop()

    sock_a, sock_b = socket.socketpair()
    watcher_a = FileWatcher(sock_a, EVENT_READ, sock_callback)
    watcher_b = FileWatcher(sock_b, EVENT_READ, sock_callback)
    eventloop.register(watcher_a)
    eventloop.register(watcher_b)

    timer = TimeWatcher(0, 1, time_callback)
    timer.count = 0
    eventloop.register(timer)
    timer = TimeWatcher(0, 1, time_callback)
    timer.count = 2
    eventloop.register(timer)

    keyint = SignalWatcher(signal.SIGINT, signal_callback)
    eventloop.register(keyint)

    sock_a.send(b'\x00')
    eventloop.run()


if __name__ == "__main__":
    test()
