#!/usr/bin/python
# -*- coding: utf-8 -*-


import os
import sys
import json
import argparse
import atexit


interface = None
module = None

username = None
password = None
obliviate = False  # Harry Potter's spell

platform = sys.platform
rooted = False


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
_config_file_path = os.path.join(os.getcwd(), "config.json")
try:
    _config_file = open(_config_file_path, "r")
    _config = json.load(_config_file)
    _config_file.close()
except (OSError, json.decoder.JSONDecodeError):
    _config = {
        "interface": None,
        "module": None,
        "default": None,
        "userlist": {}
    }
    _config_file = open(_config_file_path, "w")
    json.dump(_config, _config_file, indent=2, sort_keys=True)
    _config_file.close()


if _config['interface']:
    interface = _config['interface']
if _config['module']:
    module = _config['module']
if _config['default'] and _config['default'] in _config['userlist']:
        username = _config['default']
        password = _config['userlist'][_config['default']]
elif _config['userlist']:
    username, password = next(iter(_config['userlist'].items()))


""" Read Configuration from command line """
_parser = argparse.ArgumentParser(prog="Campus Network Fucker")

_parser.add_argument("-i", "--interface", help="network interface name")
_parser.add_argument("-m", "--module", help="authentication module")

_parser.add_argument("-u", "--username", help="username used in authentication")
_parser.add_argument("-p", "--password", help="password used in authentication")
_parser.add_argument("-o", "--obliviate", action="store_true", help="forget my username and password")

# _parser.add_argument("--rooted", help="root privilege enabled")


_args = _parser.parse_args()
_dirty = False

if _args.module:
    module = _args.module
    _dirty = True
if _args.interface:
    interface = _args.interface
    _dirty = True

if _args.username:
    username = _args.username
    _dirty = True
if _args.password:
    password = _args.password
    _dirty = True
if _args.obliviate:
    obliviate = True


def _save_dirty():
    """ Save modified configuration to file """
    if not obliviate and not _dirty:
        return

    file = open(_config_file_path, "w")

    _config['interface'] = interface
    _config['module'] = module
    if obliviate:
        if username:
            if username == _config['default']:
                _config['default'] = None
            if username in _config['userlist']:
                del _config['userlist'][username]
    else:
        if username and password:
            _config['default'] = username
            _config['userlist'][username] = password

    json.dump(_config, file, indent=2, sort_keys=True)
    file.close()


atexit.register(_save_dirty)
del os, sys, argparse
