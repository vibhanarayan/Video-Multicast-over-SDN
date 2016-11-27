import sys
import os
import socket
import subprocess
from os.path import join

CONTROLLER_IP = "10.0.2.15"
SERVER_PORT = 8000

video_id = raw_input("enter video id ")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print "Sending join message to controller"
sock.sendto(video_id, (CONTROLLER_IP, SERVER_PORT))
sock.close()

#receiving MCIP from controller
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", SERVER_PORT))
data, address = sock.recvfrom(2048)
print data

currentDir = os.getcwd()
video_path = raw_input("Enter path of video to stream (relative path): ")
filepath = join(currentDir, video_path)
rate = raw_input("Enter encoding rate: ")

#command = "vlc-wrapper -vvv %s --sout '#transcode{vcodec=h264,acodec=mpga,ab=128,channels=2,samplerate=44100}:http{mux=ffmpeg{mux=flv},dst='%s':8080/}' --sout-keep"%(filepath, data)
command = "vlc-wrapper -vvv %s --sout '#transcode{vcodec=h264,vb=%s,scale=Auto,acodec=mpga,ab=128,channels=2,samplerate=44100}:rtp{dst='%s',port=5000,mux=ts}' --sout-keep"%(filepath, rate, data)
print command

p = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE)
 
while True:
    out = p.stderr.read(1)
    if out == '' and p.poll() != None:
        break
    if out != '':
        sys.stdout.write(out)
        sys.stdout.flush()

