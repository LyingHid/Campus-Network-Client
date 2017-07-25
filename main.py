#!/usr/bin/python
# -*- coding: utf-8 -*-

import selectors

import protocol
import transport
import packets.standard

eventloop = selectors.DefaultSelector()

config = {}

parsers = {}
parsers['top'  ] = []
parsers['8021x'] = []
parsers['eapol'] = []

builders = {}
builders['ether' ] = []
builders['8021x' ] = []
builders['bottom'] = []


packets.standard.init(parsers, builders)
rj_protocol = protocol.EapProtocol(config)
raw_transport = transport.RawTransport('enp3s0', parsers, builders, rj_protocol, eventloop)

while True:
    results = eventloop.select()
    for key, events in results:
        key.data(events)
