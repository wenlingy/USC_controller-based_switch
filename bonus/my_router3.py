
"""
2017 Spring EE_555 Final Project --- Part 2 Advanced Topology : Three-Switch-Network

Group Member:
Han Zheng      Hanzheng@usc.edu
Duoyao Zhang   Duoyaozh@usc.edu
Wenling Yang   Wenlingy@usc.edu

Contact groupmenmber for project related issues

Go to https://github.com/mininet/openflow-tutorial for more information about OpenFlow information

"""
'''
Bonus Advanced Topology-- Three-Switch-Network

The controller my_router3 stored as my_router3.py

This implements a controller function on a 3-switch-forward-network
For this static layer-3 forwader/switch, it implement the control of the following topology:

Three linear connected switches plus 2 hosts for switch1, 1 host for switch2 and 1 host for switch3:

   host1 --- switch1 --- switch2 --- switch3 --- host4
                |           |
              host2        host3

'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr

log = core.getLogger()

TABLE1 = ['00:00:00:00:00:01', '00:00:00:00:00:02']
TABLE2 = ['00:00:00:00:00:03', '10:00:00:00:00:00', '30:00:00:00:00:00']
TABLE3 = ['00:00:00:00:00:04']
class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.routing_table = {}
        self.routing_table[1] = {'10.0.1.2': ['10.0.1.2', 
                                             's1-eth1', 
                                             '10.0.1.1', 
                                             1, 
                                             '00:00:00:00:00:01'],
                                '10.0.1.3': ['10.0.1.3',
                                             's1-eth2', 
                                             '10.0.1.1', 
                                             2, 
                                             '00:00:00:00:00:02'],
                                '10.0.2.0/24': ['10.0.2.1',
                                                's1-eth3',
                                                '10.0.2.1',
                                                3,
                                                '20:00:00:00:00:00'],
                                '10.0.3.0/24': ['10.0.3.1',
                                                's1-eth3',
                                                '10.0.3.1',
                                                3,
                                                '20:00:00:00:00:00']
                                }

        self.routing_table[2] = {'10.0.1.0/24': ['10.0.1.1',
                                                 's2-eth1',
                                                 '10.0.1.1',
                                                 1,
                                                 '10:00:00:00:00:00'],

                                 '10.0.2.2':    ['10.0.2.2', 
                                                 's2-eth2', 
                                                 '10.0.2.1', 
                                                  2, 
                                                 '00:00:00:00:00:03'],
                                '10.0.3.0/24': ['10.0.3.1', 
                                                's2-eth3', 
                                                '10.0.3.1', 
                                                3, 
                                                '30:00:00:00:00:00']
                                }
        self.routing_table[3] = {'10.0.1.0/24': ['10.0.1.1',
                                                  's3-eth1',
                                                  '10.0.1.1',
                                                  1,
                                                  '20:00:00:00:00:00'],
                                 '10.0.2.0/24': ['10.0.2.1',
                                                  's3-eth1',
                                                  '10.0.2.1',
                                                  1,
                                                  '20:00:00:00:00:00'],
                                 '10.0.3.2':    ['10.0.3.2',
                                                 's3-eth2',
                                                 '10.0.3.1',
                                                 2,
                                                 '00:00:00:00:00:04']}

    def get_table_num(self, packet):
        str_mac = str(packet.src)
        if str_mac in TABLE1:
            return 1
        elif str_mac in TABLE2:
            return 2
        elif str_mac in TABLE3:
            return 3
        return 4

    def find_subnet(self, dst_ip, table_num):
        if table_num <= 3:
            for subnet in self.routing_table[table_num].keys():
                if dst_ip.inNetwork(subnet):
                    return subnet, table_num
        elif table_num == 4:            
            for subnet in self.routing_table[1].keys():
                if dst_ip.inNetwork(subnet):
                    return subnet, 1
            for subnet in self.routing_table[3].keys():
                if dst_ip.inNetwork(subnet):
                    return subnet, 3
        return None, None

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
        table_num = self.get_table_num(packet)
        if packet.type == pkt.ethernet.ARP_TYPE:
            if packet.payload.opcode == pkt.arp.REQUEST:
                log.debug("ARP request received")
                # create a ARP type packet
                arp_reply = pkt.arp()
                if table_num == 1:
                    arp_reply.hwsrc = adr.EthAddr("10:00:00:00:00:00")
                elif table_num == 2:
                    arp_reply.hwsrc = adr.EthAddr("20:00:00:00:00:00")
                elif table_num == 3:
                    arp_reply.hwsrc = adr.EthAddr("30:00:00:00:00:00")
                elif table_num == 4:
                    log.debug("ERROR!!!! THIS WONT EXECUTE!!!")
                    raise Exception("ERROR!!!! THIS WONT EXECUTE!!!")
                    arp_reply.hwsrc = adr.EthAddr("20:00:00:00:00:00")

                log.debug("ARP received from %s" % packet.payload.hwsrc)
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
            subnet, table_num = self.find_subnet(dst_ip, table_num)
            # Handle ICMP type packet
            if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
                icmp_packet = ip_packet.payload
                if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
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
                    packet.dst = adr.EthAddr(self.routing_table[table_num][subnet][4])
                    self.send_EtherNet_packet(packet, self.routing_table[table_num][subnet][3]) 

    def watch_packet(self, packet, packet_in):
        log.debug("Packet src = %s" % packet.src)
        log.debug("Packet dst = %s" % packet.dst)
        log.debug("In-Packet src = %d" % packet_in.in_port)
        # log.debug("In-Packet dst = %s" % packet_in.dst)


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
        # self.watch_packet(packet, packet_in)



def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)