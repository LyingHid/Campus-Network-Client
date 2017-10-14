#!/usr/bin/python

import subprocess
import re
import socket
import struct


def get_adapters():
    command = 'ip link show'

    ip_result = subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')
    ip_result = ip_result.stdout.split('\n')

    adapters = []
    for i in range(0, len(ip_result), 2):
        adapter = re.search(r'.*: ((enp|wlp)\w+):.*<.*UP.*>.*', ip_result[i])
        if adapter:
            adapters.append(adapter.group(1))

    return adapters


def set_adapter_address(adapter):
    command = 'dhcpcd -w ' + adapter
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')


def get_adapter_dhcp_info(adapter):
    command = 'dhcpcd -U ' + adapter

    ip_result = subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')
    ip_result = ip_result.stdout.split('\n');

    info = {}
    info['ipv4'] = socket.inet_aton(ip_result[7][11:])
    info['mask'] = socket.inet_aton(ip_result[11][12:])
    info['gateway'] = socket.inet_aton(ip_result[9][8:])
    info['dns'] = socket.inet_aton(ip_result[6][21:].split()[0])

    return info


def get_adapter_socket(adapter):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x888E))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((adapter, 0x888E))
    sock.setblocking(False)

    return (sock, sock.getsockname()[4])


if __name__ == "__main__":
    print(get_adapters())
    print(get_adapter_dhcp_info('enp5s0'))
