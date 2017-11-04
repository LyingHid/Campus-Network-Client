#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import base64
import pickle
import sys
import os

import network


"""
parse configs by the command line arguments,
load configs from file as default values,
store them back to the file.
"""


FILE_NAME = 'client.conf'


def parse_arguments():
    global db

    parser = argparse.ArgumentParser(prog="Campus Network Fucker")

    parser.add_argument("-u", help="username used in authentication")
    parser.add_argument("-p", help="password used in authentication")
    parser.add_argument("-n", help="network interface name")
    parser.add_argument("-l", action='store_true', help="list available network interface")
    parser.add_argument("-r", help="resume unmanaged device to network manager")

    args = parser.parse_args()

    if args.l:
        print('available network interface:')
        for adapter in network.get_adapters():
            print(adapter)
        quit(0)
    if args.r:
        print('set ' + args.r + ' managed by network manager')
        network.attach_network_manager(args.r)
        quit(0)

    if args.u:
        db['user']['username'] = args.u.encode()
    if args.p:
        db['user']['password'] = args.p.encode()
    if args.n:
        db['nic'] = args.n


def load_from_file():
    global db

    if os.path.isfile(sys.modules[__name__].__file__) is False:
        return

    directory = os.path.dirname(sys.modules[__name__].__file__)
    fin = open(directory + '/' + FILE_NAME, 'rb')
    persist = pickle.load(fin)

    persist['password'] = base64.b64decode(persist['password'])

    if db['user']['username'] is None:
        db['user']['username'] = persist['username']
    if db['user']['password'] is None:
        db['user']['password'] = persist['password']
    if db['nic'] is None:
        db['nic'] = persist['nic']

    fin.close()


def store_to_file():
    global db

    directory = os.path.dirname(sys.modules[__name__].__file__)

    persist = {}
    persist['username'] = db['user']['username']
    persist['password'] = db['user']['password']
    persist['nic'] = db['nic']

    persist['password'] = base64.b64encode(persist['password'])

    fout = open(directory + '/' + FILE_NAME, 'wb')
    pickle.dump(persist, fout)
    fout.close()


db = {}

db['user'] = {}
db['user']['username'] = None
db['user']['password'] = None

db['nic'] = None

db['packet'] = {}
db['packet']['parsers'] = {}
db['packet']['parsers']['ether'] = []
db['packet']['parsers']['8021x'] = []
db['packet']['parsers']['eapol'] = []
db['packet']['builders'] = {}
db['packet']['builders']['ether'] = []
db['packet']['builders']['8021x'] = []
db['packet']['builders']['eapol'] = []
