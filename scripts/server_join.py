import sys
import os
import socket

CONTROLLER_IP = "10.0.2.15"
SERVER_PORT = 8000
video_id = raw_input()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print "Sending join message to controller"
sock.sendto(video_id, (CONTROLLER_IP, SERVER_PORT))

data, address = sock.recvfrom(2048)
print data

