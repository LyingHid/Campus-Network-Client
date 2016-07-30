#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import json
import argparse


interface = None
module = None

username = None
password = None


""" Change CWR to program's root directory """
os.chdir(os.path.dirname(os.path.abspath(__file__)))


""" Read Configuration from file
File content format: JSON

Example:
  {
    "interface": "enp5s0",
    "module": "hust",
    "default": "Glove An",
    "userlist": {
      "Glove An": "123456",
      "An Glove": "654321"
    }
  }
"""
config_file_path = os.path.join(os.getcwd(), "config.json")
if os.path.isfile(config_file_path):
    config_file = open(config_file_path, "r")
    config = json.load(config_file)
else:
    config = {
        "interface": None,
        "module": None,
        "default": None,
        "userlist": {}
    }
    config_file = open(config_file_path, "w")
    json.dump(config, config_file, indent=2)
config_file.close()

if config['interface']:
    interface = config['interface']
if config['module']:
    module = config['module']
if config['default'] and config['default'] in config['userlist']:
        username = config['default']
        password = config['userlist'][config['default']]
elif config['userlist']:
    username, password = next(iter(config['userlist'].items()))

print(interface, module, username, password)

""" Read Configuration from command line """
parser = argparse.ArgumentParser(prog="Campus Network Fucker")

parser.add_argument("-u", "--username", help="username used in authentication")
parser.add_argument("-p", "--password", help="password used in authentication")
parser.add_argument("-n", "--interface", help="network interface name")

parser.add_argument("--os", help="operating system name")
parser.add_argument("--rooted", help="process has root privilege")

# linux specific
parser.add_argument("--uid", help="original user id of linux os")
parser.add_argument("--gid", help="original group id of linux os")

args = parser.parse_args()


if 'username' in args:
    username = args.username
if 'password' in args:
    password = args.password
if 'interface' in args:
    interface = args.interface
