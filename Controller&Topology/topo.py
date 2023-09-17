#!/usr/bin/python

from mininet.cli import CLI
from mininet.log import lg, info
from mininet.node import Node , RemoteController
from mininet.topolib import TreeNet
from mininet.util import quietRun
from functools import partial
#################################
def startNAT( root, inetIntf='enp0s3', subnet='192.168.2.0/24' ):
    localIntf =  root.defaultIntf()

    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Create default entries for unmatched traffic
    root.cmd( 'iptables -P INPUT ACCEPT' )
    root.cmd( 'iptables -P OUTPUT ACCEPT' )
    root.cmd( 'iptables -P FORWARD DROP' )

    # Configure NAT
    root.cmd( 'iptables -I FORWARD -i', localIntf, '-d', subnet, '-j DROP' )
    root.cmd( 'iptables -A FORWARD -i', localIntf, '-s', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -A FORWARD -i', inetIntf, '-d', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -t nat -A POSTROUTING -o ', inetIntf, '-j MASQUERADE' )

    # Instruct the kernel to perform forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=1' )

def stopNAT( root ):
    """Stop NAT/forwarding between Mininet and external network"""
    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Instruct the kernel to stop forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=0' )

def fixNetworkManager( root, intf ):
    cfile = '/etc/network/interfaces'
    conf = '/etc/resolv.conf' 
    line = '\niface %s inet manual\n' % intf
    dns = '\ndns-nameservers 8.8.8.8 8.8.4.4\n'
    confdns = '\nnameserver 8.8.8.8\n'
    config = open( cfile ).read()
    if ( line ) not in config:
        print('*** Adding', line.strip(), 'to', cfile)
        with open( cfile, 'a' ) as f:
            f.write( line )
        config = open( cfile ).read()
    print('*** Adding DNS', confdns.strip(), 'to', conf)
    with open( conf, 'w' ) as f:
        f.write( confdns )
    root.cmd( 'service network-manager restart' )

def connectToInternet( network, switch='s1', rootip='192.168.2.100', subnet='192.168.2.0/24'):
    switch = network.get( switch )
    prefixLen = subnet.split( '/' )[ 1 ]
    routes = [ subnet ]  # host networks to route to
    root = Node( 'root', inNamespace=False )

    fixNetworkManager( root, 'root-eth0' )

    link = network.addLink( root, switch )
    link.intf1.setIP( rootip, prefixLen )

    network.start()
    startNAT( root )

    # Establish routes from end hosts
    for host in network.hosts:
        host.cmd( 'ip route flush root 0/0' )
        host.cmd( 'route add -net', subnet, 'dev', host.defaultIntf() )
        host.cmd( 'route add default gw', rootip )
        print("disable ipv6")
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        
    for sw in network.switches:
        print("disable ipv6")
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        
    return root

if __name__ == '__main__':
    lg.setLogLevel( 'info')
    net = TreeNet(depth=1, fanout=4, ipBase='192.168.2.0/24',controller=partial(RemoteController, ip='127.0.0.1', port=6633 ))
    rootnode = connectToInternet(net)
    print("*** Hosts are running and should have internet connectivity")
    print("*** Type 'exit' or control-D to shut down network")
    CLI(net)
    #stopNAT(rootnode)
    net.stop()
