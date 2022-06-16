from numpy import insert
from scapy.all import sniff
import pyshark

rtp_list=[]
first_time=0
cap=pyshark.FileCapture('forensic.pcap', display_filter='rtp and ip.src==172.25.105.40')
raw_audio = open('audio.g711u','wb')
def fill():rtp_list.append(b'')
for i in cap:
<<<<<<< HEAD
    if len(i)>3:rtp=i[3]
=======
    if len(i)>2:rtp=i[3]
>>>>>>> e336e6388f18e9198c65a249bd6583b4dddae7af
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
<<<<<<< HEAD
    raw_audio.write(audio)
=======
    raw_audio.write(audio)
>>>>>>> e336e6388f18e9198c65a249bd6583b4dddae7af
