
"""
2017 Spring EE_555 Final Project --- Part 1 Router exercise

Group Member:
Han Zheng      Hanzheng@usc.edu
Duoyao Zhang   Duoyaozh@usc.edu
Wenling Yang   Wenlingy@usc.edu

Contact groupmenmber for project related issues

Go to https://github.com/mininet/openflow-tutorial for more information about OpenFlow information

"""
'''
PART_1 Router Exercises

The controller file my_router1 stored as my_router1.py

This implements router function on a layer 3 switch.
For this static layer-3 forwader/switch, it consists of three subnets: 
    10.0.1.0/24, 10.0.2.0/24 and 10.0.3.0/24. 

The host1(10.0.1.100/24) is connected through interface 
s1-eth1. The host2(10.0.2.100/24) is connected through interface s1-eth2. The host3
(10.0.3.100/24) is connected through interface s1-eth3. 

The IP addresses for three interfaces is 10.0.1.1, 10.0.2.1 and 10.0.3.1, respectively.
The topology is one switch with three hosts connected as follows:
                     
                 host --- switch --- host
                             |
                            host

'''


from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr

log = core.getLogger()



class Tutorial (object):
    
    def __init__ (self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}
        self.ip_to_port = {"10.0.1.1":1,"10.0.2.1":2,"10.0.3.1":3}
        self.routing_table = {  '10.0.1.0/24': ['10.0.1.100', 
                                                's1-eth1', 
                                                '10.0.1.1', 
                                                1, 
                                                '00:00:00:00:00:01'],
                                '10.0.2.0/24': ['10.0.2.100',
                                                's1-eth2', 
                                                '10.0.2.1', 
                                                2, 
                                                '00:00:00:00:00:02'],
                                '10.0.3.0/24': ['10.0.3.100', 
                                                's1-eth3', 
                                                '10.0.3.1', 
                                                3, 
                                                '00:00:00:00:00:03']
                                }

    def find_subnet(self, dst_ip):
        for subnet in self.routing_table.keys():
            if dst_ip.inNetwork(subnet):
                return subnet
        return None

    def send_EtherNet_packet(self, ether_pkt, port):        
        msg = of.ofp_packet_out()
        msg.data = ether_pkt.pack()
        # Add an action to send to the specified port
        action = of.ofp_action_output(port=port)
        msg.actions.append(action)
        # Send message to switch
        self.connection.send(msg)

    def create_icmp_packet(self, src_ip, dst_ip, icmp_reply_type, icmp_payload):
        icmp_reply = pkt.icmp()
        icmp_reply.type = icmp_reply_type
        icmp_reply.payload = icmp_payload

        ip_p = pkt.ipv4()
        ip_p.srcip = dst_ip
        ip_p.dstip = src_ip
        ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
        ip_p.payload = icmp_reply
        return ip_p


    def create_Ether_packet(self, packet_type, src, dst, packet_in):
        eth_p = pkt.ethernet()
        eth_p.type = packet_type
        eth_p.src = src 
        eth_p.dst = dst
        eth_p.payload = packet_in
        return eth_p


    def act_like_router (self, packet, packet_in):
        # handle ARP type packet
        if packet.type == pkt.ethernet.ARP_TYPE:
            if packet.payload.opcode == pkt.arp.REQUEST:
                log.debug("ARP request received")
                # create a ARP type packet
                arp_reply = pkt.arp()
                arp_reply.hwsrc = adr.EthAddr("10:00:00:00:00:00") # self MAC
                arp_reply.hwdst = packet.payload.hwsrc
                arp_reply.opcode = pkt.arp.REPLY
                arp_reply.protosrc = packet.payload.protodst
                arp_reply.protodst = packet.payload.protosrc
                # create a ETHERNET type packet
                # wrap ARP as the payload of the ETHERNET packet
                eth_p = self.create_Ether_packet(   pkt.ethernet.ARP_TYPE,
                                                    packet.dst,
                                                    packet.src,
                                                    arp_reply)
                # Send the ETHERNET packet
                self.send_EtherNet_packet(eth_p, packet_in.in_port)
                log.debug("ARP reply sent")

            elif packet.payload.opcode == pkt.arp.REPLY:
                log.debug ("It's a reply!" )
                self.mac_to_port[packet.src] = packet_in.in_port
            else:
                log.debug( "Some other ARP opcode" )

        # Handle IP type packet
        elif packet.type == pkt.ethernet.IP_TYPE:
            # Parse IP_packet information
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
            subnet = self.find_subnet(dst_ip)
            # Handle ICMP type packet
            if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
                icmp_packet = ip_packet.payload
                if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
                    log.debug("ICMP request received")
                    # When subnet is found in the routing table
                    if subnet != None:
                        log.debug("ICMP reply sent")
                        log.debug("network containing host: "+ subnet)
                        ech = pkt.echo()
                        ech.seq = icmp_packet.payload.seq + 1
                        ech.id = icmp_packet.payload.id

                        ip_p = self.create_icmp_packet(src_ip, dst_ip, pkt.TYPE_ECHO_REPLY, ech)
                        eth_p = self.create_Ether_packet( pkt.ethernet.IP_TYPE,
                                                          packet.dst,
                                                          packet.src,
                                                          ip_p)
                        self.send_EtherNet_packet(eth_p, packet_in.in_port)
                    # Subnet is not fount, return an unreachable message
                    else:
                        log.debug("ICMP destination unreachable")
                        unr = pkt.unreach()
                        unr.payload = ip_packet
                                                
                        ip_p = self.create_icmp_packet(src_ip, dst_ip, pkt.TYPE_DEST_UNREACH, unr)
                        eth_p = self.create_Ether_packet( pkt.ethernet.IP_TYPE,
                                                          packet.dst,
                                                          packet.src,
                                                          ip_p)                        
                        self.send_EtherNet_packet(eth_p, packet_in.in_port)
            # Handle normal IP type packet
            else:
                if subnet != None:
                    packet.src = packet.dst
                    packet.dst = adr.EthAddr(self.routing_table[subnet][4])
                    self.send_EtherNet_packet(packet, self.routing_table[subnet][3]) 


    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp # The actual ofp_packet_in message.

        # Comment out the following line and uncomment the one after
        # when starting the exercise.
        self.act_like_router(packet, packet_in)



def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)