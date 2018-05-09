
"""
2017 Spring EE_555 Final Project --- OpenFlow Protocol 

Group Member:
Han Zheng      Hanzheng@usc.edu
Duoyao Zhang   Duoyaozh@usc.edu
Wenling Yang   Wenlingy@usc.edu

Contact groupmenmber for project related issues

Go to https://github.com/mininet/openflow-tutorial
for more information about OpenFlow information

"""
"""
This implements firewall function on a layer 2 switch.
The firewall rules are stored in firewall_policy.csv. 
Acoording to tutorial's command, we block communication 
between host 2 and host 3.

The topology is one switch with three hosts connected.
  host --- switch --- host
              |
             host
"""

# import from openflow
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.addresses import EthAddr, IPAddr


import datetime
import os 
import csv

log = core.getLogger()

class Firewall_switch (object):
  """
  we pass connection object to the __init__ function.
  """
  
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    log.debug("mac to port dictionary setup")

    # open firewall_policy.csv this file using 'rb' mode
    self.fireawall_file = open('pox/misc/firewall_policy.csv', 'rb')
    self.firewall_reader = csv.reader(self.fireawall_file, delimiter=',') # delimiter is ','

    self.firewall_rules = self.readfile()
    #close this file when read rules from it
    self.fireawall_file.close()

  def readfile (self):
    # Read the firewall rules file (firewall_policy.csv)
    print 'read firewall file with rules'
    self.iterator_line = iter(self.firewall_reader)
    # pass the first line which is directory of firewall file
    next(self.iterator_line)
    firewall_rules = []
    for line in self.iterator_line:
        firewall_rules.append(line[0:])
        print 'firewall rule from file '
        print line
    return firewall_rules 

  def _handle_PacketIn(self, event):
    print 'handle packet in is here'
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    self.mac_to_port[(event.connection, packet.src)] = event.port
    out_port = self.mac_to_port.get((event.connection, packet.dst))

    #if packet.dst in self.mac_to_port:
    
    if out_port is not None:
      # we need to push a flow entry. Moreover, we can install 
      # a bidirectinal flow

      # install flow entry with inverse direction
      msg = of.ofp_flow_mod()
      msg.match.dl_dst = packet.src
      msg.match.dl_src = packet.dst
      msg.actions.append(of.ofp_action_output(port = event.port))
      event.connection.send(msg)

      # install flow entry in the direction that 
      # packet just came and go out, also we should
      # send this packet out 
      msg = of.ofp_flow_mod()
      msg.data = event.ofp  # fill message content and prepare to send out
      msg.match.dl_src = packet.src
      msg.match.dl_dst = packet.dst
      msg.actions.append(of.ofp_action_output(port = out_port))
      event.connection.send(msg)
      log.debug("Installing %s.%i -> %s.%i AND %s.%i -> %s.%i" %
        (packet.dst, out_port, packet.src, event.ofp.in_port,
        packet.src, event.ofp.in_port, packet.dst, out_port))

    else:
      # packet.dst is not in mac_to _port then we should flood it
      # to all other port except the port that packet came in
      msg = of.ofp_packet_out()
      msg.data = event.ofp
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)


    
    
    
  def _handle_ConnectionUp (self, event):
    # once the switch boots up, we need to install firewall rules
    connection = event.connection
    log.debug("Switch %s boots up.", dpid_to_str(connection.dpid))

    # firewall_rules is a list stored rules
    for line in self.firewall_rules:
      if line[0] == 'mac':
        #line[1] store the source mac address
        mac_source = line[1]
        #line[2] store the destination mac address
        mac_dest = line[2]

        # install ethernet rule from source -> destination 
        msg = of.ofp_flow_mod()
        msg.match.dl_src = EthAddr(mac_source)
        msg.match.dl_dst = EthAddr(mac_dest)
        log.debug('install Ethernet firewall %s -> %s' % (mac_source, mac_dest))
        event.connection.send(msg)

        # # install ethernet rule from destination -> source
        msg = of.ofp_flow_mod()
        msg.match.dl_src = EthAddr(mac_dest)
        msg.match.dl_dst = EthAddr(mac_source)
        event.connection.send(msg)
        log.debug('install Ethernet firewall %s -> %s' % (mac_dest, mac_source))

    log.debug("firewall installed")


def launch ():
  """
  Starts the firewall_switch
  """
  def start_switch (event):
    print "Wenling is here!\n" # for debug
    log.debug("Controlling %s" % (event.connection,))
    Firewall_switch(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)