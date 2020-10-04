#!/usr/bin/env python
#
# Confiure DHCP for EdgeOS.
#
# -*- coding: utf-8 -*-

version = '1.0.0'

import argparse
import itertools
import re
import subprocess as sp
import sys

sys.path.append('../lib')

from lan import domain, networks, machines, router_dot, isp, machine_addr, subnet_addr
from command import update_router

global commands
commands = []

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
        'Configure DHCP for EdgeOS.')

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

    # Configure DHCP.
    commands.append("set service dhcp-server disabled false")
    commands.append("set service dhcp-server use-dnsmasq disable")
    commands.append("set service dns forwarding system")

    for dns in isp['dns']:
        commands.append("set system name-server 127.0.0.1")
        commands.append("set service dns forwarding name-server {}".format(dns))

    commands.append("commit")
    commands.append("save")

    for net, info in networks.items():
        iface = info['iface']
        subnet = info['subnet']
        subnet_cidr = subnet + '.0/24'
        router = subnet_addr(net, router_dot)
        vlan = info['vlan']

        start = subnet + '.64'
        stop = subnet + '.128'

        viface = iface + '.' + vlan if vlan else iface

        if net != 'ext':
            commands.append("set service dns forwarding listen-on {}".format(viface))
            commands.append("set service dhcp-server shared-network-name {} authoritative enable".format(net))
            commands.append("set service dhcp-server shared-network-name {} subnet {} default-router {}".format(net, subnet_cidr, router))
            commands.append("set service dhcp-server shared-network-name {} subnet {} dns-server {}".format(net, subnet_cidr, router))
            commands.append("set service dhcp-server shared-network-name {} subnet {} lease 86400".format(net, subnet_cidr))
            commands.append("set service dhcp-server shared-network-name {} subnet {} start {} stop {}".format(net, subnet_cidr, start, stop))
            commands.append("set service dhcp-server shared-network-name {} subnet {} domain-name {}".format(net, subnet_cidr, domain))
#            commands.append("set service dns forwarding options dhcp-range={},{},12h".format(start, stop))
            commands.append("commit")
            commands.append("save")

    commands.append("set service dns forwarding options domain={}".format(domain))
    commands.append("set system domain-name {}".format(domain))
    commands.append("set service dns forwarding options all-servers")

    commands.append("commit")
    commands.append("save")

    for name, info in machines.items():
        nets = info['net']
        mac = info['mac']
        if mac:
            for net in nets:
                qual_name = name if len(nets) == 1 else name + '-' + net
                addr = subnet_addr(net, info['addr'])
                subnet_cidr = networks[net]['subnet'] + '.0/24'

                commands.append("set service dhcp-server shared-network-name {} subnet {} static-mapping {} ip-address {}".format(net, subnet_cidr, qual_name, addr))
                commands.append("set service dhcp-server shared-network-name {} subnet {} static-mapping {} mac-address {}".format(net, subnet_cidr, qual_name, mac))
                commands.append("set system static-host-mapping host-name {}.{} inet {}".format(qual_name, domain, addr))
                commands.append("set system static-host-mapping host-name {}.{} alias {}".format(qual_name, domain, qual_name))
#                commands.append("set service dns forwarding options dhcp-host={},{}".format(mac, addr))
                commands.append("commit")
                commands.append("save")

    update_router(commands, do_update=user_opts.update_config_boot)
