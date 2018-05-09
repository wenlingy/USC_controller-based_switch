"""Custom topology example
Three linear connected switches plus 2 hosts for switch1, 1 host for switch2 and 1 host for switch3:

   host1 --- switch1 --- switch2 --- switch3 --- host4
                |           |
              host2        host3

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host1 = self.addHost("h1", ip="10.0.1.2/24", defaultRoute = "via 10.0.1.1")
        host2 = self.addHost("h2", ip="10.0.1.3/24", defaultRoute = "via 10.0.1.1")
        host3 = self.addHost("h3", ip="10.0.2.2/24", defaultRoute = "via 10.0.2.1")
        host4 = self.addHost("h4", ip="10.0.3.2/24", defaultRoute = "via 10.0.3.1")
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')

        # Add links
        self.addLink(host1, switch1)
        self.addLink(host2, switch1)
        self.addLink(host3, switch2)
        self.addLink(host4, switch3)

        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)


topos = { 'mytopo': ( lambda: MyTopo() ) }
