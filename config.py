#!/usr/bin/python
# -*- coding: utf-8 -*-


import argparse


username = None
password = None

interface = None


parser = argparse.ArgumentParser(prog="Campus Network Fucker")
parser.add_argument("-u", "--username", help="username used in authentication")
parser.add_argument("-p", "--password", help="password used in authentication")
parser.add_argument("-n", "--interface", help="network interface name")
args = parser.parse_args()


if 'username' in args:
    username = args.username
if 'password' in args:
    password = args.password
if 'interface' in args:
    interface = args.interface
