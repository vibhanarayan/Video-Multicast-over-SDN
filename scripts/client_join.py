import sys
import os
import socket
import subprocess

CONTROLLER_IP = "10.0.2.15"
CLIENT_PORT = 8001

video_id = raw_input("input video id ")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print "Sending client join message to controller"
sock.sendto(video_id, (CONTROLLER_IP, CLIENT_PORT))
sock.close()

#receiving MCIP from controller
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("",CLIENT_PORT))
data, address = sock.recvfrom(2048)
print data

cache_size=raw_input("Enter cache buffer size: ")
#command = "vlc-wrapper http://%s:8080"%data
command = "vlc-wrapper rtp://%s:5000 --network-caching=%s"%(data,cache_size)
print command

p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)

while True:
    out = p.stderr.read(1)
    if out == '' and p.poll() != None:
        break
    if out != '':
        sys.stdout.write(out)
        sys.stdout.flush()


