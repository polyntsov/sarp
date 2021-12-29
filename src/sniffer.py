import socket
import struct
import binascii
import sys

class Config:
    interface = ""
    file = sys.stdout

    @staticmethod
    def print(name, value):
        print("{0:<15} {1}".format(name + ':', value), file = Config.file)

class EtherType:
    ETH_P_ALL = 0x0003 # Every packet
    ETH_P_ARP = 0x0806 # Address Resolution packet

class EtherHeader:
    SIZE = 14 # should not be changed

    def __init__(self, dest_mac, src_mac, ethertype):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.ethertype = ethertype

    def print(self):
        Config.print("Dest MAC",
                     binascii.hexlify(self.dest_mac).decode())
        Config.print("Source MAC",
                     binascii.hexlify(self.src_mac).decode())

    @staticmethod
    def parse(buf):
        ethernet_detailed = struct.unpack("!6s6s2s", buf)
        header = EtherHeader(*ethernet_detailed)
        return header

class ARPHeader:
    SIZE = 28 # should not be changed

    def __init__(self, htype, ptype, hlen, plen, oper, sha, spa, tha, tpa):
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.oper = oper
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa


    def print(self):
        opcode = "REQUEST" if int.from_bytes(self.oper, "big") == 1 else "REPLY"
        Config.print("Opcode", opcode)
        Config.print("Source MAC", binascii.hexlify(self.sha).decode())
        Config.print("Source IP", socket.inet_ntoa(self.spa))
        Config.print("Dest MAC", binascii.hexlify(self.tha).decode())
        Config.print("Dest IP", socket.inet_ntoa(self.tpa))

    @staticmethod
    def parse(buf):
        arp_detailed = struct.unpack("!2s2s1s1s2s6s4s6s4s", buf)
        header = ARPHeader(*arp_detailed)
        return header

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

        ether_header = EtherHeader.parse(packet[0:EtherHeader.SIZE])

        # convert from network byte order (always big)
        if int.from_bytes(ether_header.ethertype, "big") != EtherType.ETH_P_ARP:
            continue

        arp_header = ARPHeader.parse(packet[EtherHeader.SIZE:
                                            EtherHeader.SIZE + ARPHeader.SIZE])

        arp_frame = '*' * 10 + " ARP FRAME " + '*' * 10
        print(arp_frame)
        arp_header.print()
        print('*' * len(arp_frame))

