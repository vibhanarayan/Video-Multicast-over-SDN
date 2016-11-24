import sys
import os
import socket

CONTROLLER_IP = "10.0.2.15"
CLIENT_PORT = 8001

video_id = raw_input("input video id")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print "Sending client join message to controller"
sock.sendto(video_id, (CONTROLLER_IP, CLIENT_PORT))
sock.close()


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("",CLIENT_PORT))
data, address = sock.recvfrom(2048)
print data

