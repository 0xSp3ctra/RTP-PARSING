from pyshark import LiveCapture
capture = LiveCapture(interface='Ethernet', display_filter='sip or rtp')
print(capture.set_debug())
for packet in capture.sniff_continuously():print(packet['IP'].src)
