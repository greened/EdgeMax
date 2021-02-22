#!/usr/bin/env python
#
# Configure a switch for EdgeOS.
#
# -*- coding: utf-8 -*-

version = '1.0.0'

import argparse
import itertools
import re
import subprocess as sp
import sys

sys.path.append('../lib')

from lan import networks, machines, router_dot, user, switch_password

global commands
commands         = []
vyatta_cmd       = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"
# vyatta_cmd                                                = "echo" # Debug

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
        'Configure a switch for EdgeOS.')

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

    # Global config
    commands.append("configure")
    commands.append("network protocol dhcp")
    commands.append("username {} password '{}' level 15".format(user, switch_password))
    commands.append("vlan participation all include 1")
#    for i in range(2, 4094):
#        commands.append("vlan participation all exclude {}".format(i))
    commands.append("no vlan port pvid all")
    commands.append("no vlan port tagging all")
    commands.append("ip routing")
    router_addr = '192.168.0' + machines['router']['addr']
    commands.append("ip route 0.0.0.0 0.0.0.0 {}".format(router_addr))
    commands.append("exit")

    # VLAN
    commands.append("network mgmt_vlan {}".format(networks['adm']['vlan']))
    commands.append("vlan database")
    for net, info in networks.items():
        vlan = info['vlan']
        if vlan:
            commands.append("vlan {}".format(vlan))
            commands.append("vlan name {} {}".format(vlan, net))
            commands.append("vlan routing {}".format(vlan))
    commands.append("exit")

    # Interface: set up VLANs.
    assigned_ports = []
    for name, info in machines.items():
        port = info['port']
        assigned_ports.append(port)
        if port:
            addr = info['addr']
            commands.append("interface 0/{}".format(port))
            commands.append("description {}".format(name))
            commands.append("ip address dhcp")
            commands.append("routing")
            nets = info['net']
            for net in nets:
                vlan = networks[net]['vlan']
                if vlan:
                    commands.append("vlan participation include {}".format(vlan))
                    if len(nets) == 1:
                        # One VLAN, assume untagged
                        commands.append("vlan pvid {}".format(vlan))
                    else:
                        # Multiple VLANs, must be tagged
                        commands.append("vlan tagging {}".format(vlan))
            commands.append("exit")

    # VLAN: Set up inter-VLAN routing
    for net, info in networks.items():
        if net != "ext":
            vlan = info['vlan']
            if vlan:
                commands.append("interface vlan {}".format(vlan))
                commands.append("ip address dhcp")
                commands.append("routing")
                commands.append("exit")

    # Set up IGMP snooping for IOT (Sonos, etc.).
    commands.append("vlan database")
    commands.append("set igmp {}".format(networks['int']['vlan']))
    commands.append("set igmp mroutrer{}".format(networks['int']['vlan']))
    commands.append("set igmp report-suppression {}".format(networks['int']['vlan']))
    commands.append("set igmp {}".format(networks['iot']['vlan']))
    commands.append("set igmp mroutrer{}".format(networks['iot']['vlan']))
    commands.append("set igmp report-suppression {}".format(networks['iot']['vlan']))
    commands.append("exit")
    commands.append("interface 0/{}".format(machines['router']['port']))
    commands.append("set igmp mrouter interface")
    commands.append("exit")


    if user_opts.update_config_boot and yesno(
            'y', 'OK to update your configuration?'):  # Open a pipe to bash and iterate commands

        #commands[:0]                                        = ["clear config", "clear pass"]
        commands.append("write memory")
        commands.append("exit")

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
