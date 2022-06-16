from numpy import insert
from scapy.all import sniff
import pyshark

rtp_list=[]
first_time=0
with pyshark.FileCapture('forensic.pcap', display_filter='rtp and ip.src==172.25.105.3') as cap:
    raw_audio = open('audio.g711u','wb')
    for i in cap:
        rtp = i[3]
        if not first_time:first_time=int(rtp.timestamp)
        #print(int(rtp.timestamp))
        try:
            rtp_list.insert(int((int(rtp.timestamp)-first_time)/160),rtp.payload.split(":"))
        except:
            rtp_list.append(b"")

    for rtp_packet in rtp_list:
        packet = " ".join(rtp_packet)
        audio = bytearray.fromhex(packet)
        raw_audio.write(audio)