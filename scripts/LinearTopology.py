from mininet.topo import Topo
from mininet.topo import LinearTopo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.util import dumpNodeConnections
from mininet.cli  import CLI
from functools import partial


def main():
    #linear topology with 7 switches and 1 host per switch
    topo = LinearTopo(7,1)
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.switches)
    dumpNodeConnections(net.hosts)
    net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
