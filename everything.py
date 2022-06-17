import pyshark
from console import getTerminalSize
from os import system
from re import sub, search

#définition des variables
sizex, sizey = getTerminalSize()
IPs = 0
started = False
first_time1, first_time2 = 0,0
m = 4 # margin
RTPs1, RTPs2 = [], []


def fill():
    if IPs[0] == packet['IP'].src:
        RTPs1.append(b'')
    else:
        RTPs2.append(b'')

capture = pyshark.FileCapture('forensic.pcap', display_filter='sip or rtp')

print('\n'*(m//2-1))

for packet in capture:
    if hasattr(packet,'sip'):
        # print(packet.sip._all_fields)
        desc = list(packet.sip._all_fields.values())[0].replace('SIP/2.0 ','').replace('SIP/2.0','')
        desc = (' '*m+('{:->'+str(sizex-m*2)+'}' if desc[0].isdigit() else '{}')).format(desc)
        print(desc)
        if hasattr(packet.sip,'sip.Method'):
            
            #récupération des IPs dans le paquet INVITE
            if packet.sip.Method == 'INVITE':
                if not IPs:
                    IPs = (packet['IP'].src,packet.sip._all_fields['sip.r-uri.host'])

                # get the sample rate from the message header :
                header = packet.sip.msg_hdr
                fs = search(r"telephone-event/([0-9])\w+", header).group()
                fs = sub(".*/", "", fs)

                #assert fs==8000
                # the codec must be G.711, else the rest won't work
                assert int(packet.sip._all_fields['sdp.media'].split(" ")[4])==0,'Unknown codec.'

            #récupération du call ID dans le paquet BYE
            elif packet.sip.Method == 'BYE':
                CID = packet.sip.call_id_generated
                print('\n'*(m//2)+'Call ended.\nCID '+CID)
                break
        elif hasattr(packet.sip,'sip.Status-Code'):
            print(packet.sip._all_fields)
            if packet.sip._all_fields['sip.Status-Code'] == '200':
                start_call_time = packet.sip.Date
                print(f"\n\n\n\n\nWWWWWIIIIINNNNNN\n\n\n\n\n\n\n\n\n\ {start_call_time}")
        else:
            print("No status code")
    else:
        if not started:
            started = True
            print(' '*m+('{:█^'+str(sizex-m*2)+'}').format(' CALL STARTED '))
        if len(packet)>3:
            rtp=packet[3]
        else:
            fill()

            continue
        if IPs[0] == packet['IP'].src and not first_time1:
            first_time1=int(rtp.timestamp)
        if IPs[0] != packet['IP'].src and not first_time2:
            first_time2=int(rtp.timestamp)
        #print(int(rtp.timestamp))

        if 'Payload' in str(rtp):
            try:
                if IPs[0] == packet['IP'].src:
                    RTPs1.insert(int((int(rtp.timestamp)-first_time1)/160), rtp.payload.split(":"))
                else:
                    RTPs2.insert(int((int(rtp.timestamp)-first_time2)/160), rtp.payload.split(":"))
            except:
                fill()
        else:
            fill()

#création de 2 fichiers au format du codec
rawL = open(f'{IPs[0]}.g711u','wb')
rawR = open(f'{IPs[1]}.g711u','wb')

#écriture des paquets RTP dans des fichiers raw
#1 fichier par sens de comm.
for rtp in RTPs1:
    rawL.write(bytearray.fromhex(" ".join(rtp)))
for rtp in RTPs2:
    rawR.write(bytearray.fromhex(" ".join(rtp)))


#conversion des fichiers raw en wav
#fusion des audios dans chaque sens pour obtenir la comm.
system(f'sox --type raw --rate {fs} -e u-law {IPs[0]}.g711u {IPs[0]}.wav')
system(f'sox --type raw --rate {fs} -e u-law {IPs[1]}.g711u {IPs[1]}.wav')
system(f'sox -M {IPs[0]}.wav {IPs[1]}.wav {CID}.wav')

CID = f"ID du call : {CID}\n"

call_infos = open('infos_call.txt', 'w')
for id in CID:
    call_infos.write(id)

