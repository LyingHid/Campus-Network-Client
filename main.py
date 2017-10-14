#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse

import protocols
import transport
import eventloop
import network


#TODO: make config a singleton
#TODO: save and load config
config = {}
config['user'] = {}


parser = argparse.ArgumentParser(prog="Campus Network Fucker")
parser.add_argument("-u", help="username used in authentication")
parser.add_argument("-p", help="password used in authentication")
parser.add_argument("-n", help="network interface name")
parser.add_argument("-l", action='store_true', help="list available network interface")
args = parser.parse_args()

if args.u:
    config['user']['username'] = args.u.encode()
if args.p:
    config['user']['password'] = args.p.encode()
if args.n:
    config['nic'] = args.n
if args.l:
    print('available network interface:')
    for adapter in network.get_adapters():
        print(adapter)
    quit(0)


config['packet'] = {}

config['packet']['parsers'] = {}
config['packet']['parsers']['ether'] = []
config['packet']['parsers']['8021x'] = []
config['packet']['parsers']['eapol'] = []

config['packet']['builders'] = {}
config['packet']['builders']['ether'] = []
config['packet']['builders']['8021x'] = []
config['packet']['builders']['eapol'] = []


loop = eventloop.Eventloop()
protocol = protocols.get_default(config)
raw_transport = transport.RawTransport(config, protocol, loop)


loop.run()
