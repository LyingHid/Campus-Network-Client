#!/usr/bin/python
# -*- coding: utf-8 -*-


""" REST API for configuration

Scheme: cnf
Location: localhost
Path: ...

The 'scheme' and 'location' will be ignored.

Example:
    cnf://localhost/config/username/Glove
    cnf://localhost/config/username
    cnf://localhost/network/available
"""


import urllib.parse

import config
import network


def request(url: str):
    pieces = urllib.parse.urlsplit(url)
    fragments = pieces[2].split('/')
    fragments.pop(0)

    category = fragments.pop(0)
    if category == 'config':
        return on_request_config(fragments)
    elif category == 'network':
        return on_request_network(fragments)


def on_request_config(fragments: list):
    length = len(fragments)

    if fragments[0] not in config.__dict__:
        return

    if length == 2:  # set
        config.__dict__[fragments[0]] = fragments[1]
        return config.__dict__[fragments[0]]
    elif length == 1:  # get
        return config.__dict__[fragments[0]]


def on_request_network(fragments: list):
    length = len(fragments)

    if length == 2:  # set
        if fragments[0] in network.__dict__:
            network.__dict__[fragments[0]] = fragments[1]
            return network.__dict__[fragments[0]]
    elif length == 1:  # get
        if fragments[0] == 'available':
            return network.available()
        elif fragments[0] in network.__dict__:
            return network.__dict__[fragments[0]]


# test and example
if __name__ == "__main__":
    test = "cnf://location/config/username/Glove"
    print(request(test))
    test = "cnf://location/config/username"
    print(request(test))
    test = "cnf://location/config/unknown"
    print(request(test))
    test = "cnf://location/network/available"
    print(request(test))
