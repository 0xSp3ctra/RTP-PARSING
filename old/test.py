import pyshark

cap=pyshark.FileCapture('forensic.pcap', display_filter='sip')
for i in cap:
    if hasattr(i.sip,'sip.Method') and i.sip.Method=='INVITE':
        start=i.sip.msg_hdr.index('telephone-event/')+16
        a=start
        while i.sip.msg_hdr[a].isdigit():a+=1
        last=a
        print(i.sip.msg_hdr[start:last])

        codec = i.sip._all_fields['sdp.media'] 
        codec = codec.split(" ")[4]
        print(codec)