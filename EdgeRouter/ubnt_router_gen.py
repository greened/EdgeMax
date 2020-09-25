#!/usr/bin/env python
#
# Configure a router for EdgeOS.
#
# -*- coding: utf-8 -*-

version = '1.0.0'

import argparse
import itertools
import re
import subprocess as sp
import sys
import os

sys.path.append('../lib')

from lan import networks, router_dot, user, router_password, isp
from command import update_router

global commands
commands         = []

edge_os = {
    'wheezy': { 'url': 'http://archive.debian.org/debian' },
    'stretch': { 'url': 'http://http.us.debian.org/debian' }
}

def get_args():
    # Enable default logging (rule 10000)
    # Defaulted to log all non-matching dropped packets
    #
    # global default_log
    # default_log                                           = user_opts.default_log

    # Set this to False unless you want to generate and write to your config.boot file
    #
    # update_config_boot                                    = user_opts.update_config_boot

    parser           = argparse.ArgumentParser(
        description  =
        'Configure a router for EdgeOS.')

    parser.add_argument(
        '-U',
        '-Update',
        action       = "store_true",
        default      =False,
        dest         ='update_config_boot',
        help         =
        'Directly configuration, commit and save config.boot - CAUTION, only use this option if you know your proposed configuration is correct.')

    parser.add_argument(
        '-v',
        '-version',
        action       = 'version',
        help         ='Show %(prog)s version and exit.',
        version      = '%(prog)s {}'.format(version))

    global user_opts

    user_opts        = parser.parse_args()

if __name__ == '__main__':
    get_args()

    commands.append("set system login user {} authentication plaintext-password '{}'".format(user, router_password))
    commands.append("set system login user {} level admin".format(user))
#    commands.append("delete system login user ubnt")

    commands.append("commit")
    commands.append("save")

    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as fd:
            for line in fd:
                match = re.search('VERSION="[0-9]+ \(([^)]+)\)"', line)
                if match:
                    release = match.group(1)
                    url = edge_os[release]['url']
                    commands.append("set system package repository {} components 'main contrib non-free'".format(release))
                    commands.append("set system package repository {} distribution {}".format(release, release))
                    commands.append("set system package repository {} url {}".format(release, url))

    commands.append("commit")
    commands.append("save")

    commands.append("set system offload ipv4 forwarding enable")
    commands.append("set system offload ipv4 gre enable")
    commands.append("set system offload ipv4 pppoe enable")
    commands.append("set system offload ipv4 vlan enable")
    commands.append("set system offload ipv4 bonding enable")

    commands.append("set system offload ipv6 forwarding enable")
    commands.append("set system offload ipv6 pppoe enable")
    commands.append("set system offload ipv6 vlan enable")

    commands.append("set system offload ipsec enable")

    commands.append("commit")
    commands.append("save")

    for net, info in networks.items():
        iface = info['iface']
        desc = info['desc']
        subnet = info['subnet']
        router = subnet + router_dot
        vlan = info['vlan']

        if vlan:
            commands.append("set interfaces ethernet {} vif {} description {}".format(iface, vlan, desc))
        else:
            commands.append("set interfaces ethernet {} description {}".format(iface, desc))

        if subnet:
            if vlan:
                commands.append("set interfaces ethernet {} vif {} address {}/24".format(iface, vlan, router))
            else:
                commands.append("set interfaces ethernet {} address {}/24".format(iface, router))
        else:
            if vlan:
                commands.append("set interfaces ethernet {} vif {} address dhcp".format(iface, vlan, router))
            else:
                commands.append("set interfaces ethernet {} address dhcp".format(iface, router))

        commands.append("commit")
        commands.append("save")

    if isp['type'] == 'pppoe':
        net = isp['net']
        iface = isp['iface']
        src_iface = networks[net]['iface']
        user = isp['user']
        password = isp['password']
        desc = isp['desc']
        vlan = networks[net]['vlan']

        if vlan:
            src_iface = src_iface + '.' + vlan

        commands.append("set interfaces pppoe {} source-interface {}".format(iface, src_iface))
        commands.append("set interfaces pppoe {} authentication user {}".format(iface, user))
        commands.append("set interfaces pppoe {} authentication password {}".format(iface, password))
        commands.append("set interfaces pppoe {} description {}".format(iface, desc))

        commands.append("commit")
        commands.append("save")
    else:
        raise Exception("Unknown isp type {}".format(isp['type']))

    update_router(commands, do_update=user_opts.update_config_boot)
