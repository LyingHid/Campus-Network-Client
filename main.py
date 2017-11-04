#!/usr/bin/python
# -*- coding: utf-8 -*-

import config
import eventloop
import protocols
import transport


config.parse_arguments()
config.load_from_file()
config.store_to_file()
loop = eventloop.Eventloop()
protocol = protocols.get_default()
raw_transport = transport.RawTransport(protocol, loop)

loop.run()
