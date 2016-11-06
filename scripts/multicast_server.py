import socket
import time
import struct
import sys

MULTICAST_GROUP = '224.1.1.1'
MULTICAST_PORT = 5001
PACKET_SIZE = 1024


def main():
    multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

    while True:
        multicast_socket.sendto("Hello!!", (MULTICAST_GROUP, MULTICAST_PORT))
        time.sleep(1)


if __name__ == '__main__':
    main()

