# Version 2: Uses Part Of The Learning Switch To Allow Traffic Flow On The Network,
# Added Packet Counter And Thresholds With Countermeasure Functions

from controller import SDNApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_5 as ofproto
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet, arp, ipv4, ipv6, tcp
from netaddr import IPAddress, IPNetwork


class Project(SDNApplication):
    # Learning Switch Code
    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)
        self.info("Project")
        # Initialize MAC Address Table
        self.mac_to_port = {}
        # Track Total Number Of TCP Packets
        self.total_packets = 1
        # PSH Packets By IP
        self.tcp_psh_packet_by_ip = dict()
        # Number Of Warnings Given
        self.warnings = dict()

    # Handler For All Packets In
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get Datapath ID To Identify OpenFlow1.3 Switches
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Analyse The Received Packets Using The Packet Library
        pkt = packet.Packet(msg.data)

        # Getting Ethernet Protocol Data
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        # Getting the IPv4 Protocol Data
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Get The Received Port Number From packet_in Message
        in_port = msg.match['in_port']

        # Show Packet Log Messages
        # self.logger.info("|Packet In -> From:   %s To:  %s |", eth_src, eth_dst)
        # More Logging Info
        self.total_packets += 1
        # print("[  " + repr(self.total_packets) + "  ]" + "  OTHER PACKET TYPE")

        # Learn MAC Address To Avoid Flood Next Time
        self.mac_to_port[dpid][eth_src] = in_port

        # If The Destination MAC Address Is Already Learned,
        # Decide Which Port To Output The Packet, Or Else Flood
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Construct Actions For Packets
        actions = [parser.OFPActionOutput(out_port)]

        # Construct packet_out Message And Send It
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

        # Retrieve the TCP part of the packet
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Looking At The TCP Packets
        if tcp_pkt is None:
            # This Is Not A TCP Packet, Ignore It
            return False

            # Detecting Only The TCP Packets With The PSH Flag
        if tcp_pkt.has_flags(tcp.TCP_PSH):
            # Detecting Only The TCP PSH Packets And Not PSH-ACK Packets
            if not tcp_pkt.has_flags(tcp.TCP_ACK):
                self.detect_tcp_psh_packets(datapath, in_port, eth_src, eth_dst)

    # Count The Number Of TCP PSH Packets From All IP Addresses
    # And Protects The Network Based On A TCP PSH Packet Limit Per IP Address
    # Blocks The IP Address And Issues A Waring Or Ban
    def detect_tcp_psh_packets(self, datapath, in_port, eth_src, eth_dst):

        if eth_src not in self.tcp_psh_packet_by_ip:
            self.tcp_psh_packet_by_ip[eth_src] = 0

        # Print Message For Differentiating PSH Packets And Other Traffic
        # print("[  " + repr(self.total_packets) + "  ]" + "  PSH PACKET")
        self.tcp_psh_packet_by_ip[eth_src] += 1

        # in_port Should Never Be The Victims Port Allowing Infinite Traffic Out (More Realistic)
        if in_port != 3:
            # Counter Begins Counting Potential TCP PSH Packets,
            # After 25000 Threshold, Countermeasures Should Be Called

            if self.tcp_psh_packet_by_ip[eth_src] > 25000:
                # Potential TCP Flood
                if eth_src not in self.warnings:
                    # Set Initial Warning Count
                    self.warnings[eth_src] = 0

                if self.warnings[eth_src] <= 3:
                    # Increase Warning Count
                    self.warnings[eth_src] += 1
                    self.launch_temp_countermeasures(datapath, eth_src)

                if self.warnings[eth_src] > 3:
                    # Increase Warning Count
                    # Doesnt Get Called Again But Can Be Used To Still Track Total Warnings Later
                    self.warnings[eth_src] += 1
                    self.launch_perma_countermeasures(datapath, eth_src)

        # Calculating A Network Load Value
        self.network_load = ((self.tcp_psh_packet_by_ip[eth_src]) / self.total_packets * 100)
        # Print Network Load For Debugging
        # print("Network Load: "+repr(self.network_load)+" %")

    # Temporary Countermeasures Function
    def launch_temp_countermeasures(self, datapath, eth_src):

        # Messages
        warning_msg = "!!Warning, Please Stop Flooding The network!!"
        temp_ban_msg = "Temporary IP Address Ban For " + repr(eth_src) + " For 60 Seconds"

        # Deploys A Block Flow Rule based On Source MAC Addresses
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth_src)

        # An Empty Action List Indicates A Drop Rule
        # Hard Coded Temporary Ban Of 60 Seconds
        self.set_flow(datapath, match, [], priority=2, hard_timeout=60)

        # Print Messages
        print(warning_msg)
        print(temp_ban_msg)

        # Reset Counter For Future Warnings
        self.tcp_psh_packet_by_ip[eth_src] = 0
        return True

    # Permanent Countermeasures Function
    def launch_perma_countermeasures(self, datapath, eth_src):

        # Messages
        warning_msg = "!!Warning, Please Stop Flooding The network!!"
        perma_ban_msg = "Permanent IP Address Ban For " + repr(eth_src) + " Indefinitely"

        # Deploys A Block Flow Rule Based On Source MAC Addresses
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth_src)

        # An Empty Action List Indicates A Drop Rule
        # idle_timeout And hard_timeout Of 0 Means There Is No Timeout
        self.set_flow(datapath, match, [], priority=2, hard_timeout=0, idle_timeout=0)

        # Print Messages
        print(warning_msg)
        print(perma_ban_msg)

        # Reset Counter For Future Warnings
        self.tcp_psh_packet_by_ip[eth_src] = 0
        return True
