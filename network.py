#!/usr/bin/python
# -*- coding: utf-8 -*-

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


def restart_adapter(adapter):
    command = 'ip link set ' + adapter + ' down'
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')
    command = 'ip link set ' + adapter + ' up'
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')


def set_adapter_address(adapter):
    command = 'nmcli connection up ifname ' + adapter
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')


def get_adapter_dhcp_info(adapter):
    command = 'nmcli -t device show ' + adapter

    ip_result = subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')

    ipv4 = re.findall(r"IP4\.ADDRESS\[1\]:(\d+\.\d+\.\d+\.\d+)", ip_result.stdout)[0]
    mask = re.findall(r"IP4\.ADDRESS\[1\]:\d+\.\d+\.\d+\.\d+/(\d+)", ip_result.stdout)
    gate = re.findall(r"IP4.GATEWAY:(\d+\.\d+\.\d+\.\d+)", ip_result.stdout)[0]
    dns1 = re.findall(r"IP4.DNS\[1\]:(\d+\.\d+\.\d+\.\d+)", ip_result.stdout)[0]

    bits = int(mask[0])
    mask = 0
    for i in range(32):
        mask <<= 1
        if bits:
            bits -= 1
            mask += 1

    info = {}
    info['ipv4'] = socket.inet_aton(ipv4)
    info['mask'] = struct.pack("!I", mask)
    info['gateway'] = socket.inet_aton(gate)
    info['dns'] = socket.inet_aton(dns1)

    return info


def get_adapter_socket(adapter):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x888E))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((adapter, 0x888E))
    sock.setblocking(False)

    return (sock, sock.getsockname()[4])


def detact_network_manager():
    command = 'nmcli -v'
    result = subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')
    return result.returncode == 0  # true if exists


def attach_network_manager(adapter):
    command = 'nmcli dev set ' + adapter + ' managed yes'
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')


def detach_network_manager(adapter):
    command = 'nmcli dev set ' + adapter + ' managed no'
    subprocess.run(command.split(), stdout=subprocess.PIPE, encoding='utf-8')


if __name__ == "__main__":
    print(get_adapters())
    print(get_adapter_dhcp_info('enp5s0'))
