from numpy import insert
from scapy.all import sniff
import pyshark

rtp_list=[]
first_time=0
cap=pyshark.FileCapture('forensic.pcap', display_filter='rtp and ip.src==172.25.105.40')
raw_audio = open('audio.g711u','wb')
def fill():rtp_list.append(b'')
for i in cap:
    if len(i)>3:rtp=i[3]
    else:
        fill()
        continue
    if not first_time:first_time=int(rtp.timestamp)
    #print(int(rtp.timestamp))
    if 'Payload' in str(rtp):rtp_list.insert(int((int(rtp.timestamp)-first_time)/160),rtp.payload.split(":"))
    else:fill()

for rtp_packet in rtp_list:
    packet = " ".join(rtp_packet)
    audio = bytearray.fromhex(packet)
    #print(audio)
    raw_audio.write(audio)