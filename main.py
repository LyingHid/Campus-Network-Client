#!/usr/bin/python
# -*- coding: utf-8 -*-

import config
import eventloop
import protocols
import transport


config.parse_arguments()
loop = eventloop.Eventloop()
protocol = protocols.get_default()
raw_transport = transport.RawTransport(protocol, loop)

loop.run()
