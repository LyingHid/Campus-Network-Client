#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import base64
import pickle
import sys
import os
import subprocess

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

    args = parser.parse_args()

    if args.l:
        print('available network interface:')
        for adapter in network.get_adapters():
            print(adapter)
        quit(0)

    if args.u:
        db['user']['username'] = args.u.encode()
    if args.p:
        db['user']['password'] = args.p.encode()
    if args.n:
        db['nic'] = args.n


def load_from_file():
    global db

    path = os.path.dirname(sys.modules[__name__].__file__)
    path = path + '/' + FILE_NAME

    if os.path.isfile(path) is False:
        return

    fin = open(path , 'rb')
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

    command = "chmod 600 " + directory + '/' + FILE_NAME
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')


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
