#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# Set to False for the full 1,350-host scale
TEST_MODE = False

TOTAL_COMP_LABS = 10
PCS_PER_COMP_LAB = 2 if TEST_MODE else 50

FACULTY_NODES = 2 if TEST_MODE else 500
DMZ_NODES = 2 if TEST_MODE else 50

TOTAL_DEPT_LABS = 10
PCS_PER_DEPT_LAB = 2 if TEST_MODE else 30


class LinuxRouter(Node):
    """Core router with IPv4 kernel forwarding enabled."""
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('iptables -F FORWARD')
        self.cmd('iptables -P FORWARD DROP')
        self.cmd('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')
        self.cmd('iptables -A FORWARD -s 10.10.0.0/16 -d 10.1.0.0/23 -j REJECT')
        self.cmd('iptables -A FORWARD -s 10.20.0.0/16 -d 10.1.0.0/23 -j REJECT')
        self.cmd('iptables -A FORWARD -d 10.2.0.0/26 -p tcp -m multiport --dports 80,443 -j ACCEPT')
        self.cmd('iptables -A FORWARD -d 10.2.0.0/26 -p icmp -j ACCEPT')
        self.cmd('iptables -A FORWARD -d 10.2.0.0/26 -p tcp --dport 5001 -j ACCEPT')
        self.cmd('iptables -A FORWARD -d 10.2.0.0/26 -p udp -j ACCEPT')

    def terminate(self):
        self.cmd('iptables -F FORWARD')
        self.cmd('iptables -P FORWARD ACCEPT')
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

class RobustOVSSwitch(OVSSwitch):
    """
    Subclass of OVSSwitch that batch-attaches interfaces in chunks of 30
    to prevent Linux PTY 4096-byte command buffer truncation at 1,350 hosts.
    """
    def start(self, controllers):
        self.cmd('ovs-vsctl --may-exist add-br %s' % self)
        self.cmd('ovs-vsctl set-fail-mode %s standalone' % self)

        # Batch interface attachments in groups of 30
        intfs = [intf.name for intf in self.intfList() if intf.name != 'lo']
        chunk_size = 30
        for i in range(0, len(intfs), chunk_size):
            chunk = intfs[i:i + chunk_size]
            cmd = 'ovs-vsctl ' + ' -- '.join(['--may-exist add-port %s %s' % (self, intf) for intf in chunk])
            self.cmd(cmd)
            for intf in chunk:
                self.cmd('ip link set %s up' % intf)

        self.cmd('ip link set %s up' % self)


def build_bits_topology():
    net = Mininet(topo=None, build=False, controller=None, switch=RobustOVSSwitch)

    info('*** Adding Central Campus Core Router (r_core)\n')
    router = net.addHost('r_core', cls=LinuxRouter, ip=None)

    router_interfaces = {}

    # 1. General Computer Labs (10 Labs, separate /26 subnets)
    info('*** Provisioning 10 General Computer Labs (500 hosts)\n')
    for lab_id in range(1, TOTAL_COMP_LABS + 1):
        sw = net.addSwitch(f's_clab{lab_id}', dpid=f'00000000000002{lab_id:02x}')
        gw_ip = f'10.10.{lab_id}.1'
        r_iface = f'r-clab{lab_id}'
        net.addLink(sw, router, intfName2=r_iface)
        router_interfaces[r_iface] = f'{gw_ip}/26'

        for pc_id in range(1, PCS_PER_COMP_LAB + 1):
            h_name = f'h_c{lab_id}_{pc_id}'
            h_ip = f'10.10.{lab_id}.{pc_id + 1}/26'
            host = net.addHost(h_name, ip=h_ip, defaultRoute=f'via {gw_ip}')
            net.addLink(host, sw)

    # 2. Faculty Subnet (10.1.0.0/23, 500 hosts)
    info('*** Provisioning Faculty Subnet (500 hosts)\n')
    s_fac = net.addSwitch('s_fac', dpid='0000000000000301')
    gw_fac = '10.1.0.1'
    net.addLink(s_fac, router, intfName2='r-fac')
    router_interfaces['r-fac'] = f'{gw_fac}/23'

    for node_id in range(1, FACULTY_NODES + 1):
        offset = node_id + 1
        third_octet = 0 if offset < 256 else 1
        fourth_octet = offset % 256
        h_ip = f'10.1.{third_octet}.{fourth_octet}/23'
        h_name = f'h_fac_{node_id}'
        host = net.addHost(h_name, ip=h_ip, defaultRoute=f'via {gw_fac}')
        net.addLink(host, s_fac)

    # 3. Server DMZ (10.2.0.0/26, 50 hosts)
    info('*** Provisioning Campus Server DMZ (50 hosts)\n')
    s_dmz = net.addSwitch('s_dmz', dpid='0000000000000401')
    gw_dmz = '10.2.0.1'
    net.addLink(s_dmz, router, intfName2='r-dmz')
    router_interfaces['r-dmz'] = f'{gw_dmz}/26'

    for srv_id in range(1, DMZ_NODES + 1):
        h_name = f'srv_dmz_{srv_id}'
        h_ip = f'10.2.0.{srv_id + 1}/26'
        host = net.addHost(h_name, ip=h_ip, defaultRoute=f'via {gw_dmz}')
        net.addLink(host, s_dmz)

    # 4. Departmental Computer Labs (10 Labs, separate /26 subnets, 300 hosts)
    info('*** Provisioning 10 Departmental Computer Labs (300 hosts)\n')
    for dept_id in range(1, TOTAL_DEPT_LABS + 1):
        sw = net.addSwitch(f's_dept{dept_id}', dpid=f'00000000000005{dept_id:02x}')
        gw_ip = f'10.20.{dept_id}.1'
        r_iface = f'r-dept{dept_id}'
        net.addLink(sw, router, intfName2=r_iface)
        router_interfaces[r_iface] = f'{gw_ip}/26'

        for pc_id in range(1, PCS_PER_DEPT_LAB + 1):
            h_name = f'h_d{dept_id}_{pc_id}'
            h_ip = f'10.20.{dept_id}.{pc_id + 1}/26'
            host = net.addHost(h_name, ip=h_ip, defaultRoute=f'via {gw_ip}')
            net.addLink(host, sw)

    info('*** Starting Network and Batched Switch Port Binding...\n')
    net.start()

    info('*** Configuring Router Interfaces and Routing Table\n')
    for intf_name, ip_cidr in router_interfaces.items():
        router.cmd(f'ip addr flush dev {intf_name}')
        router.cmd(f'ip addr add {ip_cidr} dev {intf_name}')
        router.cmd(f'ip link set dev {intf_name} up')

    info('*** 1,350-Host Campus Topology Ready.\n')
    CLI(net)

    info('*** Stopping Network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build_bits_topology()
