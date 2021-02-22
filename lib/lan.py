user = 'dag'
router_password = '3Dg#$(&%#$@^s#01'
switch_password = '3Dg#s@*%ch@^s#01'

domain = 'obbligato.org'

router_dot = '.1'
switch_dot = '.2'

isp = {
    'type': 'pppoe',
    'desc': 'ISP',
    'net': 'ext',
    'iface': 'eth0',
    'vlan': '201',
    'pppoe': '0',
    'user': 'greenedavid799@centurylink.net',
    'password': 'tWsJ2P8H',
    'dns': [ '205.171.3.26', '205.171.2.26' ]
}

# Interfaces: map name to interace, subnet and VLAN port.  -1 for no VLAN.
networks = {
    'ext': { 'iface': 'eth0', 'subnet': '', 'vlan': '201', 'pppoe': '0', 'desc': 'External' },
    'con': { 'iface': 'eth2', 'subnet': '10.0.10', 'vlan': '', 'pppoe': '', 'desc': 'Console' },
    'int': { 'iface': 'eth3', 'subnet': '10.0.20', 'vlan': '2', 'pppoe': '', 'desc': 'Internal' },
    'iot': { 'iface': 'eth3', 'subnet': '10.0.30', 'vlan': '3', 'pppoe': '', 'desc': 'IOT' },
    'dmz': { 'iface': 'eth3', 'subnet': '10.0.40', 'vlan': '4', 'pppoe': '', 'desc': 'DMZ' },
    'gst': { 'iface': 'eth3', 'subnet': '10.0.50', 'vlan': '5', 'pppoe': '', 'desc': 'Guest' },
    'adm': { 'iface': 'eth3', 'subnet': '10.0.90', 'vlan': '9', 'pppoe': '', 'desc': 'Admin' }
}

machines = {
    'router': { 'net': ['int', 'iot', 'gst', 'dmz', 'adm'], 'mac': '', 'addr': router_dot, 'port': '25' },
    'switch': { 'net': ['int', 'iot', 'gst', 'dmz', 'adm'], 'mac': 'f0:9f:c2:3f:f9:a2', 'addr': switch_dot, 'port': '' },
    'switch-cons-adm': { 'net': ['adm'], 'mac': '00:e0:4c:68:37:bb', 'addr': '.101', 'port': '1' },
    'switch-cons-int': { 'net': ['int'], 'mac': '00:e0:4c:68:37:bb', 'addr': '.102', 'port': '2' },
    'wap1': { 'net': ['int', 'gst', 'adm'], 'mac': '98:da:c4:65:2e:96', 'addr': '.3', 'port': '3' },
    'wap2': { 'net': ['int', 'gst', 'adm'], 'mac': '98:da:c4:65:32:24', 'addr': '.4', 'port': '4' },
    'tv': { 'net': ['int'], 'mac': '', 'addr': '.5', 'port': '5' },
    'avr': { 'net': ['int'], 'mac': '', 'addr': '.6', 'port': '6' },
    'ps5': { 'net': ['iot'], 'mac': '', 'addr': '.7', 'port': '7' },
    'printer': { 'net': ['iot'], 'mac': '9c:ad:97:b4:63:45', 'addr': '.8', 'port': '8' },
    'bluebird': { 'net': ['int'], 'mac': '02:11:32:25:25:03', 'addr': '.23', 'port': '23' },
    'victor': { 'net': ['int'], 'mac': '00:11:32:7f:7d:10', 'addr': '.24', 'port': '24' },
    'davidmac': { 'net': ['int'], 'mac': '38:f9:d3:51:d4:00', 'addr': '.50', 'port': '' },
    'emilymac': { 'net': ['int'], 'mac': 'dc:a9:04:88:e6:43', 'addr': '.51', 'port': '' },
    'davidphone': { 'net': ['int'], 'mac': '3c:28:6d:21:2d:3a', 'addr': '.52', 'port': '' },
    'emilyphone': { 'net': ['int'], 'mac': '60:b7:6e:36:97:fc', 'addr': '.53', 'port': '' },
    'sonosonekitchen': {'net': ['iot'], 'mac': '48:a6:b8:f2:cf:2e', 'addr': '.54', 'port': ''},
    'washer': {'net': ['iot'], 'mac': '40:2f:86:b1:15:cd', 'addr': '.55', 'port': ''},
    'dryer': {'net': ['iot'], 'mac': '40:2f:86:7d:c3:ad', 'addr': '.56', 'port': ''},
    'chromecast': {'net': ['iot'], 'mac': '', 'addr': '.57', 'port': ''},
}

def machine_addr(machine):
    net = machines[machine]['net']

    if len(net) > 1:
        raise Exception('Machine {} does not have a unique address (nets {})'.format(machine, net))

    net = net[0]

    subnet = networks[net]['subnet']
    addr = subnet + machines[machine]['addr'] if subnet else machines[machine]['addr']
    return addr

def subnet_addr(net, addr):
    net = networks[net]
    subnet = net['subnet']
    if subnet:
        addr = subnet + addr
    return addr
