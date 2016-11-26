from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import CPULimitedHost, RemoteController, OVSSwitch
from mininet.util import dumpNodeConnections, custom
from mininet.cli  import CLI


class CustomTopology(Topo):
    def __init__(self):
        super(CustomTopology, self).__init__()

        #Create all switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')
        s5 = self.addSwitch('s5', protocols='OpenFlow13')
        s6 = self.addSwitch('s6', protocols='OpenFlow13')
        s7 = self.addSwitch('s7', protocols='OpenFlow13')

        #Create all hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')
        h10 = self.addHost('h10')
        h11 = self.addHost('h11')
        h12 = self.addHost('h12')

        #Links between hosts and switches
        self.addLink(s3, h1, port1=1, port2=1)
        self.addLink(s3, h2, port1=2, port2=1)
        self.addLink(s3, h3, port1=3, port2=1)
        self.addLink(s4, h4, port1=1, port2=1)
        self.addLink(s4, h5, port1=2, port2=1)
        self.addLink(s4, h6, port1=3, port2=1)
        self.addLink(s6, h7, port1=1, port2=1)
        self.addLink(s6, h8, port1=2, port2=1)
        self.addLink(s6, h9, port1=3, port2=1)
        self.addLink(s7, h10, port1=1, port2=1)
        self.addLink(s7, h11, port1=2, port2=1)
        self.addLink(s7, h12, port1=3, port2=1)

        #links petween switches 
        self.addLink(s1, s2, port1=1, port2=3)
        self.addLink(s1, s5, port1=2, port2=3)
        self.addLink(s2, s3, port1=1, port2=4)
        self.addLink(s2, s4, port1=2, port2=4)
        self.addLink(s5, s6, port1=1, port2=4)
        self.addLink(s5, s7, port1=2, port2=4)


def main():
    topo = CustomTopology()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController, switch=OVSSwitch, autoSetMacs=True)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.switches)
    dumpNodeConnections(net.hosts)
    net.pingAll()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()

