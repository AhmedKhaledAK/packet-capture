import socket
import binascii

class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    addr = ""
    i = 0
    while i < len(raw_ip_addr):
        if i == len(raw_ip_addr) - 1:
            addr+= str(raw_ip_addr[i] & 0xFF)
        else:
            addr+= str(raw_ip_addr[i] & 0xFF) + "."
        i+=1

    return addr


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section

    print("src port:", ip_packet_payload[0:2])
    srcport = int.from_bytes(ip_packet_payload[0:2], byteorder="big")
    print("srcport:", srcport)
    print("dest port:", ip_packet_payload[2:4])
    destport = int.from_bytes(ip_packet_payload[2:4], byteorder="big")
    print("destport:", destport)

    print("12:",ip_packet_payload[12])
    offset = (ip_packet_payload[12] & 0xF0) >> 4
    print("data offset:", offset)

    data = getdata(offset, ip_packet_payload)

    print("tcp data:", data)

    return TcpPacket(-1, -1, -1, b'')

def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section

    # print("ip_packet:",ip_packet)
    # print("len:", len(ip_packet))
    # print("1st byte:",ip_packet[0])
    ihl = ip_packet[0] & 0x0F
    # print("ihl:",ihl)
    # print("10th byte:", ip_packet[9])
    protocol = ip_packet[9] & 0xFF
    # print("protocol:", protocol)
    # print("12-15", ip_packet[12:16])
    srcaddr = parse_raw_ip_addr(ip_packet[12:16])
    # print("srcaddr:", srcaddr)
    # print("16-19", ip_packet[16:20])
    destaddr  = parse_raw_ip_addr(ip_packet[16:20])
    #print("destaddr:", destaddr)

    data = getdata(ihl, ip_packet)
    # print("data len:", len(data))
    # print("data:", data)

    print("hex packet:", binascii.hexlify(ip_packet))
    print("hex data:", binascii.hexlify(data))

    return IpPacket(protocol, ihl, srcaddr, destaddr, data)

def getdata(offset, packet):
    start = int(offset*32/8)
    return packet[start:]


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    
    TCP = 0x0006    # this is the protocol number of TCP in hex
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)

    while True:
        # Receive packets and do processing here
        bindata, addr = sniffer.recvfrom(5000)
        ippacket = parse_network_layer_packet(bindata)
        parse_application_layer_packet(ippacket.payload)
        print("addr:", addr)

if __name__ == "__main__":
    main()