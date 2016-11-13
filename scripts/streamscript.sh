#!/bin/bash
#vlc-wrapper -vvv ~/Downloads/jimmy.mp4 --sout '#transcode{vcodec=h264,vb=80,scale=Auto,acodec=mpga,ab=128,channels=2,samplerate=44100}:http{mux=ffmpeg{mux=flv},dst=10.0.0.1:8080/}' --sout-keep
vlc-wrapper -vvv $1 --sout '#transcode{vcodec=h264,vb=$2,scale=Auto,acodec=mpga,ab=128,channels=2,samplerate=44100}:http{mux=ffmpeg{mux=flv},dst='$3':8080/}' --sout-keep
