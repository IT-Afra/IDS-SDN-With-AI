from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):
    def build(self, **_opts):
        # Add 2 routers in four different subnets
        R1 = self.addHost('R1', cls=LinuxRouter, ip='192.168.1.10/24')
        R2 = self.addHost('R2', cls=LinuxRouter, ip='192.168.2.10/24')


        # Add 4 switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4') 

        # Add Links Between Sw And R
        self.addLink(sw1,
                     R1,
                     intfName2='R1-eth1',
                     params2={'ip': '192.168.1.10/24'})

        self.addLink(sw2,
                     R1,
                     intfName2='R1-eth2',
                     params2={'ip': '192.168.1.10/24'})

        self.addLink(sw3,
                     R2,
                     intfName2='R2-eth1',
                     params2={'ip': '192.168.2.10/24'})

        self.addLink(sw4,
                     R2,
                     intfName2='R2-eth2',
                     params2={'ip': '192.168.2.10/24'})

        # Add Links Between Routers
        self.addLink(R1,
                     R2,
                     intfName1='R1-eth3',
                     intfName2='R2-eth3',
                     params1={'ip': '192.168.100.1/24'},
                     params2={'ip': '192.168.100.2/24'})
    
    
        # Adding hosts 
        ho1 = self.addHost(name='ho1',
                          ip='192.168.1.100/24',
                          defaultRoute='via 192.168.1.10')
        ho2 = self.addHost(name='ho2',
                          ip='192.168.1.101/24',
                          defaultRoute='via 192.168.1.10')
    
        ho3 = self.addHost(name='ho3',
                          ip='192.168.2.100/24',
                          defaultRoute='via 192.168.2.10')
                      
        ho4 = self.addHost(name='ho4',
                          ip='192.168.2.101/24',
                          defaultRoute='via 192.168.2.10')

        # Add host-switch links
        self.addLink(ho1, sw1)
        self.addLink(ho2, sw2)
        self.addLink(ho3, sw3)
        self.addLink(ho4, sw4)


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, controller=RemoteController)

    # Add routing for reaching networks that aren't directly connected
    info(net['R1'].cmd("ip route add 192.168.2.0/24 via 192.168.100.2 dev R1-eth3"))
    info(net['R2'].cmd("ip route add 192.168.1.0/24 via 192.168.100.1 dev R2-eth3"))



    net.start()
    CLI(net)
    net.stop()


if name == 'main':
    setLogLevel('info')
    run()