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
        # Add router
        R1 = self.addHost('R1', cls=LinuxRouter, ip='192.168.1.10/24')

        # Add switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')


        # Add Links Between Sw And R
        self.addLink(sw1,
                     R1,
                     intfName2='R1-eth1',
                     params2={'ip': '192.168.1.10/24'})

        self.addLink(sw2,
                     R1,
                     intfName2='R1-eth2',
                     params2={'ip': '192.168.1.10/24'})


        # Adding hosts
        ho1 = self.addHost(name='ho1',
                           ip='192.168.1.100/24',
                           defaultRoute='via 192.168.1.10')
        ho2 = self.addHost(name='ho2',
                           ip='192.168.1.101/24',
                           defaultRoute='via 192.168.1.10')

        ho3 = self.addHost(name='ho3',
                           ip='192.168.1.103/24',
                           defaultRoute='via 192.168.1.10')

        ho4 = self.addHost(name='ho4',
                           ip='192.168.1.104/24',
                           defaultRoute='via 192.168.1.10')

        # Add host-switch links
        self.addLink(ho1, sw1)
        self.addLink(ho2, sw1)
        self.addLink(ho3, sw2)
        self.addLink(ho4, sw2)


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, controller=RemoteController)


    net.start()
    CLI(net)
    net.stop()


if name == 'main':
    setLogLevel('info')
    run()