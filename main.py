#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import selectors

import packets.standard
import packets.ruijie
import protocols
import transport
import eventloop


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
config['packet'] = {}
config['packet']['parsers'] = parsers
config['packet']['builders'] = builders


loop = eventloop.Eventloop()
protocol = protocols.RuijieProtocol(config)
raw_transport = transport.RawTransport(config, protocol, loop)

loop.run()
