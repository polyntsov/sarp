import socket
import struct
import binascii
import oui_parser
from enum import Enum

class Config:
    interface = ""

class EtherType:
    ETH_P_ALL = 0x0003 # Every packet
    ETH_P_ARP = 0x0806 # Address Resolution packet

class EtherHeader:
    SIZE = 14 # should not be changed

    def __init__(self, dest_mac, src_mac, ethertype):
        self.dest_mac = binascii.hexlify(dest_mac).decode()
        self.src_mac = binascii.hexlify(src_mac).decode()
        # convert from network byte order (always big)
        self.ethertype = int.from_bytes(ethertype, "big")

    def print(self):
        print_format("Dest MAC", self.dest_mac)
        print_format("Source MAC", self.src_mac)

    @staticmethod
    def parse(buf):
        ethernet_detailed = struct.unpack("!6s6s2s", buf)
        header = EtherHeader(*ethernet_detailed)
        return header

    @staticmethod
    def add_colon(mac):
        return ":".join(mac[i:i+2] for i in range(0, len(mac), 2))

class ARPHeader:
    SIZE = 28   # should not be changed

    # operation type
    REQUEST = 1 # should not be changed
    REPLY = 2   # should not be changed

    def __init__(self, htype, ptype, hlen, plen, oper, sha, spa, tha, tpa):
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        is_request = int.from_bytes(oper, "big") == ARPHeader.REQUEST
        self.oper = ARPHeader.REQUEST if  is_request else ARPHeader.REPLY
        self.sha = binascii.hexlify(sha).decode()
        self.spa = spa
        self.tha = binascii.hexlify(tha).decode()
        self.tpa = tpa

    def print(self):
        opcode = "REQUEST" if self.oper == ARPHeader.REQUEST else "REPLY"
        print_format("Opcode", opcode)
        print_format("Source MAC", EtherHeader.add_colon(self.sha))
        print_format("Source IP", socket.inet_ntoa(self.spa))
        print_format("Dest MAC", EtherHeader.add_colon(self.tha))
        print_format("Dest IP", socket.inet_ntoa(self.tpa))

    @staticmethod
    def parse(buf):
        arp_detailed = struct.unpack("!2s2s1s1s2s6s4s6s4s", buf)
        header = ARPHeader(*arp_detailed)
        return header

def print_format(name, value):
    print("{0:<20} {1}".format(name + ':', value))

def create_socket():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.htons(EtherType.ETH_P_ALL))

    # if interface is specified bind socket to it
    if Config.interface != None:
        s.bind((Config.interface, 0))

    return s

def sniff():
    s = create_socket()

    while True:
        packet = s.recv(EtherHeader.SIZE + ARPHeader.SIZE)

        ether_header = EtherHeader.parse(packet[:EtherHeader.SIZE])

        if ether_header.ethertype != EtherType.ETH_P_ARP:
            continue

        arp_header = ARPHeader.parse(packet[EtherHeader.SIZE:
                                            EtherHeader.SIZE + ARPHeader.SIZE])

        arp_frame = '*' * 18 + " ARP FRAME " + '*' * 18
        print(arp_frame)
        arp_header.print()
        m = oui_parser.parse_oui("oui.txt")
        print_format("Source MAC Vendor", f"{m[arp_header.sha[:6]]}")
        if arp_header.oper == ARPHeader.REPLY:
            print_format("Dest MAC Vendor", f"{m[arp_header.tha[:6]]}")
        print('*' * len(arp_frame))

