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


def yesno(*args):

    if len(args) > 1:
        default                                             = args[0].strip().lower()
        question                                            = args[1].strip()
    elif len(args) == 1:
        default                                             = args[0].strip().lower()
        question                                            = 'Answer y or n:'
    else:
        default                                             = None
        question                                            = 'Answer y or n:'

    if default == None:
        prompt                                              = " [y/n] "
    elif default == "y":
        prompt                                              = " [Y/n] "
    elif default == "n":
        prompt                                              = " [y/N] "
    else:
        raise ValueError(
            "{} invalid default parameter: \'{}\' - only [y, n] permitted".format(
                __name__, default))

    while 1:
        sys.stdout.write(question + prompt)
        choice                                              = (raw_input().lower().strip() or '')
        if default is not None and choice == '':
            if default == 'y':
                return True
            elif default == 'n':
                return False
        elif default is None:
            if choice == '':
                continue
            elif choice[0] == 'y':
                return True
            elif choice[0] == 'n':
                return False
            else:
                sys.stdout.write("Answer must be either y or n.\n")
        elif choice[0] == 'y':
            return True
        elif choice[0] == 'n':
            return False
        else:
            sys.stdout.write("Answer must be either y or n.\n")

if __name__ == '__main__':
    get_args()

    commands.append("set system login user {} authentication plaintext-password {}".format(user, router_password))
    commands.append("set system login user {} level admin".format(user))
    commands.append("delete system login user ubnt")

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

    commands.append("set system offload ipv4 forwarding enable")
    commands.append("set system offload ipv4 gre enable")
    commands.append("set system offload ipv4 pppoe enable")
    commands.append("set system offload ipv4 vlan enable")
    commands.append("set system offload ipv4 bonding enable")

    commands.append("set system offload ipv6 forwarding enable")
    commands.append("set system offload ipv6 pppoe enable")
    commands.append("set system offload ipv6 vlan enable")

    commands.append("set system offload ipsec enable")

    commands.append("delete interfaces")

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
    else:
        raise Exception("Unknown isp type {}".format(isp['type']))

    if user_opts.update_config_boot and yesno(
            'y', 'OK to update your configuration?'):  # Open a pipe to bash and iterate commands

        commands[:0]                                        = ["begin"]
        commands.append("commit")
        commands.append("save")
        commands.append("end")

        vyatta_shell                                        = sp.Popen(
            'bash',
            shell=True,
            stdin                                           = sp.PIPE,
            stdout=sp.PIPE,
            stderr                                          = sp.PIPE)
        for cmd in commands:  # print to stdout
            print cmd
            vyatta_shell.stdin.write('{} {};\n'.format(vyatta_cmd, cmd))

        out, err                                            = vyatta_shell.communicate()

        cfg_error                                           = False
        if out:
            if re.search(r'^Error:.?', out):
                cfg_error                                   = True
            print "configure message:"
            print out
        if err:
            cfg_error                                       = True
            print "Error reported by configure:"
            print err
        if (vyatta_shell.returncode == 0) and not cfg_error:
            print "Configuration was successful."
        else:
            print "Configuration was NOT successful!"

    else:
        for cmd in commands:
            #print "echo %s" % cmd
            print cmd
