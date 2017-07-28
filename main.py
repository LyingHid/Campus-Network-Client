#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import selectors

import packets.standard
import packets.ruijie
import protocols
import transport


config = {}
config['user'] = {}

parser = argparse.ArgumentParser(prog="Campus Network Fucker")
parser.add_argument("-u", help="username used in authentication")
parser.add_argument("-p", help="password used in authentication")
parser.add_argument("-n", help="network interface name")
args = parser.parse_args()

if 'u' in args:
    config['user']['username'] = args.u.encode()
if 'p' in args:
    config['user']['password'] = args.p.encode()
if 'n' in args:
    config['nic'] = args.n


eventloop = selectors.DefaultSelector()


parsers = {}
parsers['top'  ] = []
parsers['8021x'] = []
parsers['eapol'] = []

builders = {}
builders['ether' ] = []
builders['8021x' ] = []
builders['bottom'] = []

packets.standard.init(parsers, builders)
packets.ruijie.init(parsers, builders)


protocol = protocols.RuijieProtocol(config)
raw_transport = transport.RawTransport(config['nic'], parsers, builders, protocol, eventloop)


while True:
    results = eventloop.select()
    for key, events in results:
        key.data(events)
