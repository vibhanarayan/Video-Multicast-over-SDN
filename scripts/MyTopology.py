from mininet.topo import Topo
from mininet.topolib import TreeTopo
from mininet.topolib import TorusTopo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.cli  import CLI

def main():
    topo = TreeTopo(3,2)
    #topo = TorusTopo(3,3)
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.switches)
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    print net
    #net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
