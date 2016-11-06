import socket
import sys
import struct

MULTICAST_GROUP = '224.1.1.1'
MULTICAST_PORT = 5001
PACKET_SIZE = 1024


def main():
    multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    multicast_socket.bind((MULTICAST_GROUP, MULTICAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data, addr = multicast_socket.recvfrom(PACKET_SIZE)
        print 'Data = %s' % data

    multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)


if __name__ == '__main__':
    main()

